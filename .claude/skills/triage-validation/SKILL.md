---
name: triage-validation
description: Finding validation before writing any report — 7-Question Gate (all 7 questions), 4 pre-submission gates, always-rejected list, conditionally valid with chain table, CVSS 3.1 quick reference, severity decision guide, report title formula, 60-second pre-submit checklist. Use BEFORE writing any report. One wrong answer = kill the finding and move on. Saves N/A ratio.
---

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


# TRIAGE & VALIDATION

One wrong answer = STOP. Kill it. Move on.

> "N/A hurts your validity ratio. Informative is neutral. Only submit what passes all 7 questions."

---

## THE 7-QUESTION GATE

Ask IN ORDER. One wrong answer = STOP immediately.

---

### Q1: Can an attacker use this RIGHT NOW, step by step?

Complete this template:
```
1. Setup:   I need [own account / another user's ID / no account]
2. Request: [exact HTTP method, URL, headers, body — copy-paste ready]
3. Result:  I can [read / modify / delete] [exact data shown in response]
4. Impact:  The real-world consequence is [account takeover / PII read / money stolen]
5. Cost:    Time: [X minutes], Capital: [$0 / $X subscription required]
```

**If you CANNOT write step 2 as a real HTTP request → KILL IT.**

---

### Q2: Is the impact on the program's accepted impact list?

Go to the program page. Find "Vulnerability Types" or "Out of Scope."

Common tiers:
- **Critical**: Any-user ATO without interaction, RCE, SQLi with data exfil, admin auth bypass
- **High**: Mass PII exfil, privilege escalation, internal SSRF with data, stored XSS all users
- **Medium**: IDOR on specific user non-critical data, XSS on sensitive page requiring click
- **Low**: Non-sensitive info disclosure, clickjacking with PoC

**If your bug maps to a listed exclusion → KILL IT.**

---

### Q3: Is the root cause in an in-scope asset?

Confirm:
- Vulnerable domain is on the in-scope list (not `*.internal.target.com`)
- It's a production asset (not staging/dev unless explicitly in scope)
- It's not a third-party service the company just uses (not Stripe, Salesforce, Google Auth)

Many HackerOne/Bugcrowd scope pages are JS-rendered SPAs — a plain fetch/curl
returns an empty shell, not the scope table. If your tooling can't render it,
don't guess in-scope status: mark it "unconfirmed, needs live check" and say so
in the verdict rather than assuming pass.

**If out-of-scope → KILL IT.**

---

### Q4: Does it require privileged access that an attacker can't realistically get?

- "Admin can do X" = centralization risk = **KILL IT** (on 99% of programs)
- "Non-admin can do X that only admin should do" = valid
- "Requires physical access / MFA device" = usually invalid
- "Requires compromised victim account to work" = questionable, low severity at best

---

### Q5: Is this already known or accepted behavior?

Search:
1. Program's HackerOne/Bugcrowd disclosed reports: Ctrl+F endpoint name + bug class
2. GitHub issues on target repo: `is:issue label:security ENDPOINT_NAME`
3. Changelog/CHANGELOG.md — does it mention this behavior?
4. API docs / design docs — is it documented as intended?

**If acknowledged/design decision → KILL IT.**

---

### Q6: Can you prove impact beyond "technically possible"?

- XSS → show actual cookie theft or session hijack, not just `alert(1)` or `alert(document.domain)`
- SSRF → hit an internal endpoint that returns data, not just DNS ping
- SQLi → show actual data exfil from a real table, not just error message
- IDOR → show actual other-user's data in response, not just a 200 status code

**If you can only show "technically possible" → DOWNGRADE severity, not kill.**

---

### Q7: Is this a known-invalid bug class?

Check the NEVER SUBMIT list below. If it's on this list without a chain → **KILL IT.**

---

### Q8: Identity check — which session found this, and does it survive?

For any finding made under an authenticated hunt, record the answer to each:

```
1. Session ID:        [12-char BBHUNT_SESSION_ID hash from audit.jsonl]
2. Identity:          [low-priv user A / high-priv user B / API key / etc.]
3. Anonymous repro:   Does the same request work with NO auth header?
4. Cross-identity:    Does it work under session B with the same data scope?
5. Stale-cred repro:  Does a logged-out / expired session still get the data?
```

Why this matters:
- **IDOR / BOLA**: must work with session A reading session B's data — if it
  only works with no auth, that's "missing auth" not IDOR (different bug,
  different severity).
- **Priv-esc**: must work with low-priv session reading high-priv data — if
  both sessions can already see it, no bug.
- **Auth bypass**: must work *without* a valid session — if it stops working
  when you log out, you've found a permissions issue, not a bypass.
- **Always check both directions**: a finding that only reproduces under
  one identity is often a real, scoped permission boundary, not a vuln.

`audit.jsonl` entries are tagged with `session_id`. Re-run the request
under each identity and confirm the bug holds before writing the report.
This is the most common reason "confirmed IDOR" findings come back as N/A.

If you cannot answer the identity questions, treat the finding as unproven.
Blank answers auto-fail on auth-related findings.

---

---

## 4 PRE-SUBMISSION GATES

Run in sequence. ALL 4 must PASS.

### Gate 0: Reality Check (30 seconds)
```
[ ] Bug is REAL — confirmed with actual HTTP requests, not code reading alone
[ ] Bug is IN SCOPE — checked program scope page explicitly
[ ] Reproducible from scratch — can reproduce starting from fresh session
[ ] Evidence ready — screenshot, response body, or video
[ ] If you're validating someone else's write-up with no credentials/session to
    replay it yourself, say so explicitly in the verdict — a desk/logic review
    of the write-up is NOT the same as live re-confirmation, and calling it
    "validated" without that caveat misleads whoever reads your verdict
```

### Gate 1: Impact Validation (2 minutes)
```
[ ] Can answer: "What can attacker DO that they couldn't before?"
[ ] Answer is more than "see non-sensitive data" (unless program pays for info disclosure)
[ ] Real victim: another user's data, company's data, financial loss
[ ] Not relying on victim doing something unlikely
```

### Gate 2: Deduplication Check (5 minutes)
```
[ ] Searched HackerOne Hacktivity for this program + similar bug title/endpoint
[ ] Searched GitHub issues for target repo
[ ] Read most recent 5 disclosed reports for this program
[ ] Not a "known issue" in their changelog or public docs
[ ] Google: "TARGET_NAME ENDPOINT_NAME bug bounty"
```

### Gate 3: Report Quality (10 minutes)
```
[ ] Title: [Bug Class] in [Endpoint] allows [actor] to [impact]
[ ] Steps to Reproduce: copy-pasteable HTTP request
[ ] Evidence: screenshot/video of actual impact (not just 200 status)
[ ] Severity: matches CVSS 3.1 score AND program's severity definitions
[ ] CVSS vector recomputed by hand (or with the FIRST.org calculator) — never
    trust a self-reported score. Self-scoring is frequently wrong: e.g.
    AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N is 6.5 (Medium) every time, not 8.7 —
    a triager will recompute it in 10 seconds and a mismatch costs you
    credibility on the rest of the report. If you believe real-world severity
    is higher than the vector gives you, argue it separately via scale/impact
    (see Downgrade Counters in report-writing) — don't inflate the CVSS number.
[ ] Remediation: 1-2 sentences of concrete fix
[ ] NEVER used "could potentially" or "may allow"
```

---

## NEVER SUBMIT LIST

Submitting these destroys your validity ratio.

```
Missing CSP / HSTS / security headers
Missing SPF / DKIM / DMARC
GraphQL introspection alone (no auth bypass, no IDOR demonstrated)
Banner / version disclosure without working CVE exploit
Clickjacking on non-sensitive pages (no sensitive action PoC)
Tabnabbing
CSV injection (no actual code execution shown)
CORS wildcard (*) without credential exfil proof of concept
Logout CSRF
Self-XSS (only exploits own account)
Open redirect alone (no ATO or OAuth theft chain)
OAuth client_secret in mobile app (known, expected)
SSRF DNS callback only (no internal service access or data)
Host header injection alone (no password reset poisoning PoC)
Rate limit on non-critical forms (search, contact, login with Cloudflare)
Session not invalidated on logout
Concurrent sessions
Internal IP in error message
Mixed content
SSL weak ciphers
Missing HttpOnly / Secure cookie flags alone
Broken external links
Autocomplete on password fields
Pre-account takeover (usually — very specific conditions required)
```

---

## COMMON N/A CLASSES — KILL SIGNALS

These pass basic gut-check but consistently come back N/A. Each row has a **specific signal** that tells you to kill it *before* writing the report.

| Finding | Why it N/As | Kill signal — if you see this, stop |
|---|---|---|
| Reflected XSS | CSP blocks execution; sandbox context; no session access | Dalfox found `alert(1)` but no cookie in response; `Content-Security-Policy` header present |
| SSRF — DNS callback only | No internal data reached; programs require HTTP response with data | Interactsh/Collaborator got DNS ping but no HTTP reply with internal content |
| IDOR — own data only | Attacker == victim; no cross-account access proven | User ID in response matches your own test account |
| SQLi — error message only | WAF filtered or error is cosmetic; no data exfiltrated | Got DB error string but no actual table rows returned |
| CORS wildcard `*` | `*` blocks `withCredentials`; no PII actually exfiltrated | `Access-Control-Allow-Credentials: true` absent; credentialed request returns 403 |
| Rate limit missing — non-sensitive endpoint | Program only pays for rate-limit on auth/payment/OTP surfaces | Endpoint handles search, contact form, or sits behind Cloudflare |
| Nuclei `info` template match | Version detection, not exploitation | Template severity is `info`; no CVE PoC executed against live service |
| MFA rate limit (no lockout) | Impact depends on OTP brute-force succeeding — it usually doesn't | 15 requests returned 200 but no OTP code was accepted |
| Open redirect alone | Redirect is informational without token theft chain | No OAuth `redirect_uri` parameter; no auth code or token in the redirected URL |
| Auth bypass — admin precondition | Requires compromised admin to trigger; attacker can't get there | "Admin can do X on behalf of user" — attacker must already be admin |
| XSS via `alert(document.domain)` | Not proof of session theft | PoC shows domain popup only; no `document.cookie` exfil, no event listener |
| SAML metadata exposed | Disclosure only — aids attack but is not standalone impact | No private key or signing cert extracted; metadata is publicly documented by IdP |

**Decision rule:** if your finding matches a kill signal → classify as `[INFORMATIONAL]`, do **not** run `/validate`, move on.

---

## CONDITIONALLY VALID — CHAIN REQUIRED

Build the chain first, prove it works end to end, THEN report.

| Standalone Finding | Chain Required | Valid Result |
|---|---|---|
| Open redirect | + OAuth redirect_uri → auth code theft | ATO (Critical) |
| Clickjacking | + sensitive action + working PoC | Medium |
| CORS wildcard | + credentialed request exfils user PII | High |
| CSRF | + sensitive action (transfer funds, change email, delete account) | High |
| Rate limit bypass | + OTP/reset token brute force succeeds | Medium/High |
| SSRF DNS-only | + internal service access + data returned | Medium |
| Host header injection | + password reset email uses injected host | High |
| Prompt injection | + reads other user's data (IDOR) | High |
| S3 bucket listing | + JS bundles contain API keys or OAuth secrets | Medium/High |
| Self-XSS | + CSRF to trigger it on victim without their knowledge | Medium |
| Subdomain takeover | + OAuth redirect_uri registered at that subdomain | Critical |
| GraphQL introspection | + auth bypass mutation or IDOR on node() | High |

---

## CVSS 3.1 QUICK REFERENCE

### Common Score Examples

| Finding | Score | Severity | Vector |
|---|---|---|---|
| IDOR read PII, any user, auth required | 6.5 | Medium | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |
| IDOR write/delete, any user | 7.5 | High | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| Auth bypass → admin panel | 9.8 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Stored XSS → cookie theft, stored | 8.8 | High | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N |
| SQLi → full DB dump | 8.6 | High | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| SSRF → cloud metadata | 9.1 | Critical | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N |
| Race → double spend | 7.5 | High | AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N |
| GraphQL auth bypass | 8.7 | High | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| JWT none algorithm | 9.1 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |

### Metric Quick Guide

| What you have | Metric | Value |
|---|---|---|
| Exploitable over internet | AV | Network (N) |
| No special timing or race | AC | Low (L) |
| Free account needed | PR | Low (L) |
| No login needed | PR | None (N) |
| Admin needed | PR | High (H) |
| No victim action | UI | None (N) |
| Victim must click | UI | Required (R) |
| Reads all data | C | High (H) |
| Reads some data | C | Low (L) |
| Modifies all data | I | High (H) |
| Crashes service | A | High (H) |
| Affects only app | S | Unchanged (U) |
| Affects browser/OS/cloud | S | Changed (C) |

---

## KILL FAST RULES

The goal is to QUICKLY disqualify bad leads so you hunt real bugs:

1. **5-minute rule**: If you can't fill in Q1's template in 5 minutes → move on
2. **Precondition count**: More than 2 preconditions simultaneously required → kill it
3. **Impact test**: "What does attacker walk away with?" — if nothing tangible → kill it
4. **Admin bypass**: "Admin can do X" is NEVER a bug → kill it immediately
5. **Design doc test**: If it's documented behavior → kill it immediately
6. **Rabbit hole signal**: 30+ min on Q6 with no reproducible PoC → kill it

---

## ANTI-PATTERNS THAT LOSE MONEY

```
Writing a report before confirming the bug exists (most common)
Submitting theoretical impact without proof
"The API returns more fields than necessary" (sensitivity matters — is it actually sensitive?)
Chaining A+B into one report when they're separate bugs (two separate payouts)
Reporting B saying "similar to A in my other report" — fresh Gate 0 for every bug
Overclaiming severity — triagers trust you less next time
Under-describing impact — triager doesn't understand why it matters
```
