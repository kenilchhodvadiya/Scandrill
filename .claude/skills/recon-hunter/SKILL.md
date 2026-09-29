---
name: recon-hunter
description: >
  Full-stack recon-to-bug skill. Runs passive + active recon, attack surface mapping, and
  bug discovery in one continuous pipeline — all phases in order, zero skips. Triggers on:
  "recon", "enumerate", "subdomain", "find bugs", "attack surface", "map the target",
  "what's exposed", "scan this", or any domain/IP handed without further instruction.
  Produces a ranked finding list with PoC curl commands. Use for unauthenticated coverage
  before any authenticated testing begins.
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


# RECON-HUNTER — Full Recon + Bug Discovery Pipeline

**One rule: impact first. Only report what an attacker can abuse RIGHT NOW.**
Kill theoretical findings before they reach the list.

---

## PHASE 0 — Setup

```bash
T="target.com"           # apex domain
OUT="~/recon/$T"
mkdir -p $OUT/{subs,urls,js,ports,screenshots,findings}
cd $OUT
```

Set `$T` from whatever scope the user hands you. If a list is given, loop every entry.

---

## PHASE 1 — Passive Subdomain Enumeration (zero-touch)

Goal: maximum breadth before touching target infra.

```bash
# Certificate transparency
curl -s "https://crt.sh/?q=%25.$T&output=json" \
  | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u >> subs/raw.txt

# subfinder (all sources)
subfinder -d $T -all -silent >> subs/raw.txt

# amass passive
amass enum -passive -d $T -o subs/amass.txt 2>/dev/null
cat subs/amass.txt >> subs/raw.txt

# chaos (ProjectDiscovery dataset)
chaos -d $T -silent 2>/dev/null >> subs/raw.txt

# github-subdomains (requires GITHUB_TOKEN env)
github-subdomains -d $T -t $GITHUB_TOKEN -o subs/github.txt 2>/dev/null
cat subs/github.txt >> subs/raw.txt

# cero (TLS SAN scraping)
cero $T 2>/dev/null >> subs/raw.txt

# deduplicate
sort -u subs/raw.txt -o subs/all.txt
wc -l subs/all.txt
```

**Bug signal during enumeration:**
- Subdomains matching `*.s3.amazonaws.com`, `*.pages.dev`, `*.netlify.app`, `*.github.io`,
  `*.azurewebsites.net`, `*.vercel.app` → queue for takeover check (Phase 4)
- `dev-`, `staging-`, `internal-`, `admin-`, `api-` prefixes → high-value targets, prioritize

---

## PHASE 2 — DNS Resolution + Live Host Discovery

```bash
# Resolve all subs to live IPs
dnsx -l subs/all.txt -resp -a -cname -silent -o subs/resolved.txt
cat subs/resolved.txt | awk '{print $1}' > subs/live_hosts.txt

# httpx — full fingerprint pass
httpx -l subs/live_hosts.txt \
  -title -tech-detect -status-code -content-length \
  -ip -cdn -cname -follow-redirects \
  -mc 200,201,204,301,302,307,401,403,404,500 \
  -o subs/httpx.json -j -silent

# Extract live HTTP hosts
cat subs/httpx.json | jq -r '.url' > subs/live_http.txt

wc -l subs/live_http.txt
```

**Bug signals:**
- `401`/`403` on `admin.*`, `internal.*`, `api.*` → queue for 403 bypass
- `500` responses → server errors, potential injection surface
- CDN=false + IP exposed → origin IP bypass candidate
- `tech-detect` shows old versions → CVE check queue

---

## PHASE 3 — Port Scanning + Service Discovery

Run only against non-CDN IPs (CDN scanning is wasteful and often out-of-scope).

```bash
# Extract non-CDN IPs from httpx output
cat subs/httpx.json | jq -r 'select(.cdn==false) | .host' | sort -u > ports/ips.txt

# Fast port scan — top 1000 + common web/service ports
naabu -l ports/ips.txt -top-ports 1000 \
  -p 80,443,8080,8443,8888,9000,9200,9300,5601,3000,3001,4000,5000,6379,27017,5432,3306,2375,2376 \
  -o ports/open.txt -silent

# Service banner + version (nmap on open ports only)
nmap -iL ports/open.txt -sV --open -T4 \
  --script=banner,http-title,http-server-header \
  -oN ports/nmap.txt -oX ports/nmap.xml 2>/dev/null
```

**High-value service signals → immediate bug checks:**

| Service | Port | Check |
|---------|------|-------|
| Elasticsearch | 9200/9300 | `curl http://IP:9200/_cat/indices` — unauth? |
| Kibana | 5601 | `curl http://IP:5601/api/status` — unauth? |
| Redis | 6379 | `redis-cli -h IP ping` — unauth? |
| MongoDB | 27017 | `mongo --host IP --eval "db.adminCommand('listDatabases')"` |
| Docker API | 2375/2376 | `curl http://IP:2375/v1.41/containers/json` |
| Kubernetes | 6443/10250 | `curl https://IP:10250/pods -k` |
| Spring Actuator | 8080/8443 | `curl http://HOST/actuator` |
| Prometheus | 9090 | `curl http://HOST:9090/metrics` |
| Grafana | 3000 | Default admin:admin login |
| Jenkins | 8080 | `curl http://HOST:8080/api/json` |

---

## PHASE 4 — Subdomain Takeover Check

```bash
# nuclei takeover templates against all live hosts
nuclei -l subs/live_http.txt \
  -t ~/nuclei-templates/takeovers/ \
  -severity medium,high,critical \
  -o findings/takeovers.txt -silent

# subjack for CNAME-based takeover
subjack -w subs/all.txt -t 100 -timeout 30 \
  -o findings/subjack.txt -ssl 2>/dev/null

# Manual check for common fingerprints
for host in $(cat subs/live_http.txt); do
  body=$(curl -sk $host)
  for sig in "There isn't a GitHub Pages site here" \
             "The specified bucket does not exist" \
             "NoSuchBucket" \
             "Repository not found" \
             "Project not found" \
             "Fastly error: unknown domain" \
             "This shop is currently unavailable" \
             "Domain not configured" \
             "404 Not Found" \
             "You're Almost There" \
             "a Netlify site"; do
    echo "$body" | grep -qi "$sig" && echo "[TAKEOVER?] $host — $sig" | tee -a findings/takeovers.txt
  done
done
```

---

## PHASE 5 — Historical URL Collection + Secret Hunting in URLs

```bash
# Collect historical URLs — three sources
for host in $(cat subs/live_hosts.txt); do
  echo $host | waybackurls 2>/dev/null >> urls/all.txt
  echo $host | gau --subs 2>/dev/null >> urls/all.txt
  waymore -i $host -mode U -oU /tmp/wm.txt 2>/dev/null
  cat /tmp/wm.txt >> urls/all.txt
done
sort -u urls/all.txt -o urls/all.txt

# Juicy extension filter
grep -iE '\.(bak|backup|sql|db|sqlite|json|xml|yaml|yml|env|config|conf|log|old|gz|zip|tar|7z|rar|pdf|xls|xlsx|doc|docx|csv|pem|key|crt|p12|pfx|jks)(\?|$)' \
  urls/all.txt > urls/juicy_extensions.txt

# Parameter URLs (injection candidates)
grep '=' urls/all.txt | grep -v '\.js\|\.css\|\.png\|\.jpg\|\.gif' > urls/params.txt

# Admin/sensitive paths
grep -iE '(admin|panel|dashboard|manage|config|debug|test|dev|staging|backup|api|graphql|swagger|actuator|metrics|health|console)' \
  urls/all.txt > urls/sensitive_paths.txt
```

**Immediate checks on juicy URLs:**
```bash
# Probe juicy files — are they still live?
httpx -l urls/juicy_extensions.txt -mc 200 -o urls/juicy_live.txt -silent
cat urls/juicy_live.txt   # every hit here is a potential finding
```

---

## PHASE 6 — Active Crawl (per live host)

```bash
while IFS= read -r HOST; do
  echo "[*] Crawling $HOST"
  
  # katana — JS-aware, follows dynamic imports
  katana -u "$HOST" -jc -jsl -d 5 -kf all -aff -silent \
    -o urls/katana_$(echo $HOST | tr '/:' '_').txt 2>/dev/null
  
  # gospider — link extraction
  gospider -s "$HOST" -d 3 --js -q 2>/dev/null \
    | grep -oP 'https?://[^\s"'"'"']+' >> urls/all.txt
  
  # hakrawler
  echo "$HOST" | hakrawler -d 3 -subs 2>/dev/null >> urls/all.txt

done < subs/live_http.txt

# Deduplicate everything collected
sort -u urls/all.txt -o urls/all.txt

# Re-extract JS files
grep -oP 'https?://[^\s"'"'"']+\.js(\?[^\s"'"'"']*)?' urls/all.txt | sort -u > js/all_js.txt
```

---

## PHASE 7 — Directory + Endpoint Fuzzing

```bash
# Use a target-derived wordlist + standard lists
cat urls/all.txt | unfurl paths | tr '/' '\n' | sort | uniq -c | sort -rn \
  | awk '$1>1{print $2}' > urls/custom_wordlist.txt

# ffuf — directory fuzzing on high-value hosts
while IFS= read -r HOST; do
  ffuf -u "$HOST/FUZZ" \
    -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-words.txt \
    -mc 200,201,204,301,302,307,401,403 \
    -ac -t 40 -timeout 10 \
    -o urls/ffuf_$(echo $HOST | tr '/:' '_').json 2>/dev/null
done < <(head -20 subs/live_http.txt)   # top 20 hosts; expand as needed

# API endpoint fuzzing
ffuf -u "TARGET/api/FUZZ" \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,204,400,401,403,405 -ac -t 30
```

---

## PHASE 8 — JavaScript Analysis + Secret Extraction

```bash
mkdir -p js/files js/secrets

# Download all JS files
while IFS= read -r url; do
  fname="js/files/$(echo $url | md5sum | cut -d' ' -f1).js"
  curl -sk "$url" -o "$fname" 2>/dev/null
done < js/all_js.txt

# Beautify
for f in js/files/*.js; do
  js-beautify "$f" -o "${f%.js}.pretty.js" 2>/dev/null
done

# Secret scanning — trufflehog on JS dir
trufflehog filesystem js/files/ --json 2>/dev/null | tee js/secrets/trufflehog.json

# gitleaks on JS dir
gitleaks detect --source=js/files/ --report-path=js/secrets/gitleaks.json \
  --no-git 2>/dev/null

# Manual grep patterns
grep -rhoP \
  '(sk-[a-zA-Z0-9]{48}|sk-proj-[a-zA-Z0-9_-]{90,}|sk-ant-[a-zA-Z0-9_-]{95,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[a-zA-Z0-9]{36}|xox[baprs]-[0-9A-Za-z-]{10,}|hf_[a-zA-Z0-9]{34}|sk_live_[a-zA-Z0-9]{24}|r8_[a-zA-Z0-9]{40}|shpss_[a-zA-Z0-9]{32}|vc_[a-zA-Z0-9]{24,}|gsk_[a-zA-Z0-9]{52})' \
  js/files/ | sort -u | tee js/secrets/manual_grep.txt

# Endpoint extraction from JS
cat js/files/*.js 2>/dev/null | grep -oP '["'"'"'`](/[a-zA-Z0-9/_-]{3,})['"'"'"`]' \
  | sort -u > urls/js_endpoints.txt

# SSR state blobs
for host in $(cat subs/live_http.txt | head -20); do
  body=$(curl -sk $host)
  echo "$body" | grep -oP 'window\.__NEXT_DATA__\s*=\s*\{.{0,2000}' \
    && echo "[SSR-NEXT] $host" >> findings/ssr_state.txt
  echo "$body" | grep -oP 'window\.__NUXT__\s*=\s*\{.{0,2000}' \
    && echo "[SSR-NUXT] $host" >> findings/ssr_state.txt
done
```

**Confirm live secrets immediately:**
```bash
# OpenAI
curl -s https://api.openai.com/v1/models -H "Authorization: Bearer $KEY" | jq '.data[0].id'

# Anthropic
curl -s https://api.anthropic.com/v1/models -H "x-api-key: $KEY" -H "anthropic-version: 2023-06-01" | jq '.models[0].id'

# AWS — identity only, never use further
aws sts get-caller-identity --no-cli-pager 2>/dev/null

# GitHub
curl -s https://api.github.com/user -H "Authorization: token $KEY" | jq '.login'

# Stripe
curl -s https://api.stripe.com/v1/charges -u "$KEY:" | jq '.object'
```

---

## PHASE 9 — Nuclei Automated Bug Scan

```bash
# Full nuclei run — critical + high + medium, all categories
nuclei -l subs/live_http.txt \
  -t ~/nuclei-templates/ \
  -severity critical,high,medium \
  -etags "dos,fuzz,bruteforce" \
  -c 30 -rl 100 \
  -o findings/nuclei_all.txt \
  -json -o findings/nuclei_all.json \
  -silent

# High-value specific template groups
nuclei -l subs/live_http.txt \
  -t ~/nuclei-templates/exposures/ \
  -t ~/nuclei-templates/misconfiguration/ \
  -t ~/nuclei-templates/cves/ \
  -t ~/nuclei-templates/default-logins/ \
  -t ~/nuclei-templates/technologies/ \
  -severity critical,high \
  -o findings/nuclei_priority.txt -silent
```

---

## PHASE 10 — Cloud Storage Enumeration

```bash
# S3 bucket guessing from target name
NAMES=("$T" "${T//./-}" "${T%%.*}" "dev-${T%%.*}" "staging-${T%%.*}" \
       "backup-${T%%.*}" "assets-${T%%.*}" "cdn-${T%%.*}" "static-${T%%.*}" \
       "${T%%.*}-prod" "${T%%.*}-dev" "${T%%.*}-stage" "${T%%.*}-backup")

for name in "${NAMES[@]}"; do
  # AWS S3
  curl -s "https://$name.s3.amazonaws.com/?list-type=2" \
    | grep -q '<Key>' && echo "[S3-PUBLIC] $name" | tee -a findings/cloud.txt
  
  # GCS
  curl -s "https://storage.googleapis.com/$name/?list-type=2" \
    | grep -q '<Key>' && echo "[GCS-PUBLIC] $name" | tee -a findings/cloud.txt

  # Azure Blob
  curl -s "https://$name.blob.core.windows.net/?comp=list" \
    | grep -q '<Container>' && echo "[AZURE-PUBLIC] $name" | tee -a findings/cloud.txt
done

# Firebase — check for unauth read
curl -s "https://${T%%.*}-default-rtdb.firebaseio.com/.json?shallow=true" \
  | grep -v '"error"' && echo "[FIREBASE-UNAUTH] ${T%%.*}" | tee -a findings/cloud.txt
```

---

## PHASE 11 — Source Code + Config Exposure

```bash
# .git exposure check
for host in $(cat subs/live_http.txt); do
  status=$(curl -so /dev/null -w '%{http_code}' "$host/.git/config")
  [ "$status" = "200" ] && echo "[GIT-EXPOSED] $host" | tee -a findings/source_exposure.txt
done

# Common config/backup files
PATHS=("/.env" "/.env.production" "/.env.local" "/config.json" "/config.yaml"
       "/wp-config.php.bak" "/database.yml" "/.htpasswd" "/web.config"
       "/settings.py" "/config.php" "/.DS_Store" "/composer.json"
       "/package.json" "/Dockerfile" "/docker-compose.yml"
       "/actuator/env" "/actuator/heapdump" "/.aws/credentials"
       "/swagger.json" "/openapi.json" "/api-docs" "/graphql")

for host in $(cat subs/live_http.txt | head -50); do
  for path in "${PATHS[@]}"; do
    code=$(curl -so /dev/null -w '%{http_code}' --max-time 5 "$host$path")
    [ "$code" = "200" ] && echo "[EXPOSED] $host$path ($code)" | tee -a findings/source_exposure.txt
  done
done
```

---

## PHASE 12 — CORS Misconfiguration Check

```bash
for host in $(cat subs/live_http.txt | head -30); do
  # Test arbitrary origin reflection
  resp=$(curl -sk -H "Origin: https://evil.com" -I "$host/api/" 2>/dev/null)
  echo "$resp" | grep -i "access-control-allow-origin: https://evil.com" \
    && echo "[CORS] $host reflects arbitrary origin" | tee -a findings/cors.txt
  
  # Null origin
  resp=$(curl -sk -H "Origin: null" -I "$host/api/" 2>/dev/null)
  echo "$resp" | grep -i "access-control-allow-origin: null" \
    && echo "[CORS-NULL] $host accepts null origin" | tee -a findings/cors.txt
done
```

---

## PHASE 13 — SSRF Entry Point Discovery

```bash
# Find URL parameters that could be SSRF entry points
grep '=' urls/params.txt \
  | grep -iE '(url|uri|endpoint|host|server|proxy|dest|destination|redirect|target|src|source|feed|webhook|callback|link|ref|return|path|load|fetch|pull|remote|request)=' \
  | sort -u > urls/ssrf_candidates.txt

wc -l urls/ssrf_candidates.txt
head -20 urls/ssrf_candidates.txt

# If candidates exist, test with collaborator/interactsh payload (manual step)
echo "[MANUAL] Replace PARAM with interactsh URL and check OOB hits"
echo "  interactsh-client -v"
echo "  curl 'CANDIDATE_URL?param=https://YOUR.oast.fun/test'"
```

---

## PHASE 14 — GraphQL Discovery + Introspection

```bash
GRAPHQL_PATHS=("/graphql" "/api/graphql" "/v1/graphql" "/query" "/gql" "/graphiql" "/playground")

for host in $(cat subs/live_http.txt | head -30); do
  for path in "${GRAPHQL_PATHS[@]}"; do
    code=$(curl -so /dev/null -w '%{http_code}' -X POST \
      -H "Content-Type: application/json" \
      -d '{"query":"{__typename}"}' \
      "$host$path" 2>/dev/null)
    [ "$code" = "200" ] && {
      echo "[GRAPHQL] $host$path"
      # Try introspection
      curl -s -X POST -H "Content-Type: application/json" \
        -d '{"query":"{ __schema { queryType { name } types { name fields { name } } } }"}' \
        "$host$path" | jq '.data.__schema.types[].name' 2>/dev/null \
        | tee -a findings/graphql.txt
    } | tee -a findings/graphql.txt
  done
done
```

---

## PHASE 15 — Org Secret Hunt (GitHub / GitLab / npm)

```bash
# TruffleHog — GitHub org scan
trufflehog github --org="$ORG_NAME" --token="$GITHUB_TOKEN" \
  --json 2>/dev/null | tee findings/trufflehog_github.json

# gitleaks — org repos
gh repo list "$ORG_NAME" --limit 200 --json nameWithOwner \
  | jq -r '.[].nameWithOwner' | while read repo; do
    gitleaks detect --repo="https://github.com/$repo" \
      --report-path="findings/gitleaks_$( echo $repo | tr '/' '_').json" 2>/dev/null
done

# noseyparker
noseyparker scan --git-url "https://github.com/$ORG_NAME" \
  -o findings/noseyparker/ 2>/dev/null

# npm package name squatting check
# Extract package names from package.json files found in recon
cat urls/all.txt | grep 'package\.json' | while read url; do
  curl -sk "$url" 2>/dev/null | jq -r '.dependencies // {} | keys[]' 2>/dev/null
done | sort -u > findings/npm_packages.txt
# Check each against npm registry — internal packages not in registry = dep confusion candidate
while read pkg; do
  code=$(curl -so /dev/null -w '%{http_code}' "https://registry.npmjs.org/$pkg")
  [ "$code" = "404" ] && echo "[DEP-CONFUSION?] $pkg not on npm" | tee -a findings/dep_confusion.txt
done < findings/npm_packages.txt
```

---

## PHASE 16 — Screenshot + Visual Triage

```bash
# Screenshot all live hosts for quick visual review
gowitness file -f subs/live_http.txt \
  --screenshot-path screenshots/ \
  --resolution 1280x800 2>/dev/null

gowitness report generate --db-path gowitness.sqlite3 \
  --open 2>/dev/null || echo "Open gowitness report manually"
```

---

## FINDINGS TRIAGE — Ranking & Output

After all phases complete, consolidate and rank:

```bash
echo "=== FINDING SUMMARY ===" > findings/REPORT.txt
echo "" >> findings/REPORT.txt

echo "--- CRITICAL ---" >> findings/REPORT.txt
cat findings/trufflehog_github.json findings/trufflehog.json 2>/dev/null \
  | jq -r '.SourceMetadata.Data.Filesystem.file + " — " + .DetectorName' >> findings/REPORT.txt
grep -h '\[S3-PUBLIC\]\|\[GCS-PUBLIC\]\|\[AZURE-PUBLIC\]\|\[FIREBASE-UNAUTH\]\|\[GIT-EXPOSED\]' \
  findings/*.txt >> findings/REPORT.txt

echo "" >> findings/REPORT.txt
echo "--- HIGH ---" >> findings/REPORT.txt
grep -h '\[TAKEOVER\]\|\[GRAPHQL\]\|\[CORS\]' findings/*.txt >> findings/REPORT.txt
grep 'critical\|high' findings/nuclei_priority.txt 2>/dev/null >> findings/REPORT.txt

echo "" >> findings/REPORT.txt
echo "--- MEDIUM ---" >> findings/REPORT.txt
cat findings/nuclei_all.txt 2>/dev/null | grep 'medium' >> findings/REPORT.txt
grep '\[EXPOSED\]' findings/source_exposure.txt >> findings/REPORT.txt
grep '\[DEP-CONFUSION\]' findings/dep_confusion.txt >> findings/REPORT.txt

echo "" >> findings/REPORT.txt
echo "--- SSRF CANDIDATES (needs manual confirm) ---" >> findings/REPORT.txt
cat urls/ssrf_candidates.txt | head -20 >> findings/REPORT.txt

cat findings/REPORT.txt
```

---

## SEVERITY KILL RULES (apply before writing any report)

- **KILL** — nuclei false positive with no live data exfil
- **KILL** — CORS without `Access-Control-Allow-Credentials: true`
- **KILL** — `.git` exposed but only shows config with no remote URL
- **KILL** — S3 bucket exists but `ListObjects` returns `AccessDenied`
- **KILL** — dep confusion package name not matching internal registry naming pattern
- **DOWNGRADE P1→P2** — secret confirmed live but read-only scope (e.g. viewer token only)
- **KEEP** — any secret that passes `sts get-caller-identity` / auth.test / `/user` endpoint

---

## PROOF-OF-CONCEPT STANDARD

Every finding must ship with a copyable curl command a triager can run in 60 seconds:

```bash
# Template
curl -sk -X GET "https://TARGET/PATH" \
  -H "Origin: https://evil.com" \
  | jq '.' | head -20
# Expected: <describe what to look for in output>
```

Data exfil cap: **50 records max**. Prefer `?shallow=true`, `?limit=1`, `COUNT(*)` over bulk pull.

---

## COVERAGE LEDGER

Check off each phase on completion. Do not declare recon done until all boxes are ticked.

- [ ] Phase 1 — Passive subdomain enum
- [ ] Phase 2 — DNS resolution + httpx fingerprint
- [ ] Phase 3 — Port scan + service discovery
- [ ] Phase 4 — Subdomain takeover
- [ ] Phase 5 — Historical URLs + juicy files
- [ ] Phase 6 — Active crawl
- [ ] Phase 7 — Directory + endpoint fuzzing
- [ ] Phase 8 — JS analysis + secret extraction
- [ ] Phase 9 — Nuclei automated scan
- [ ] Phase 10 — Cloud storage enum
- [ ] Phase 11 — Source/config exposure
- [ ] Phase 12 — CORS misconfig
- [ ] Phase 13 — SSRF entry points
- [ ] Phase 14 — GraphQL discovery
- [ ] Phase 15 — Org secret hunt
- [ ] Phase 16 — Screenshots
- [ ] Triage + ranked report generated
