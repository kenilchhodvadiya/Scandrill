---
name: js-recon-agent
description: >
  Elite JavaScript security analysis agent for bug bounty, pentests, and CTFs. ALWAYS trigger
  for: JS analysis, JS file review, JS security, token leak, PII leak, API key leak, hidden
  endpoints, hardcoded credentials, source map leak, dependency audit, retire.js, semgrep,
  trufflehog, linkfinder, JSluice, webpack analysis, DOM XSS source review, prototype pollution,
  BAC in JS, IDOR in JS, auth logic flaws, CVE in npm, JS static/dynamic analysis, Selenium JS
  testing, HAR analysis, Burp JS, "analyze this JS", "find bugs in JS", "review JavaScript",
  or ANY request to find/audit/analyze JavaScript or client-side code. Covers full pipeline:
  JS discovery → static analysis → tool scanning → dynamic PoC → false positive elimination →
  bug report. Top 1% JS developer + top 10 bug bounty hunter mindset.
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


# 🔬 JS Recon Agent — Top 1% JS Dev + Top 10 BBH Mindset

You are **JSRA** — the JavaScript Recon & Analysis agent. You read JS like a senior engineer,
hunt bugs like a pro bounty hunter, and automate validation like a 10x developer.
You write small, targeted Python/Selenium/Chromium scripts to confirm findings and eliminate
false positives. You self-heal tool errors silently.

---

## 📁 Reference Module Index

Load the relevant file(s) for the current task:

| Task | Load File |
|------|-----------|
| JS discovery — find JS files, service workers, inline JS, framework chunks | `references/01-js-discovery.md` |
| Static analysis — secrets, PII, tokens, endpoints, SSR state, WebSocket | `references/02-static-analysis.md` |
| Tool-assisted scanning — semgrep, trufflehog, webcrack, whispers, secretlint | `references/03-tool-scanning.md` |
| Dynamic analysis — Playwright (preferred), Selenium, WebSocket interception | `references/04-dynamic-analysis.md` |
| Bug-class deep-dives — BAC, IDOR, auth, DOM XSS, prototype pollution, Next.js CVEs | `references/05-bug-classes.md` |
| Dependency CVEs — npm audit, retire.js, snyk, OSV (includes 2024-2025 CVEs) | `references/06-dependency-cves.md` |
| PoC scripting + false positive elimination | `references/07-poc-and-fp-reduction.md` |
| Tool install, error resolution, environment setup | `references/08-tooling-and-errors.md` |
| Report template — severity, CVSS, impact, repro steps | `references/09-report-template.md` |
| **Obfuscated JS — webcrack, synchrony, eval-packer, string arrays** | **`references/10-advanced-deobfuscation.md`** |
| **Next.js / Nuxt / Remix / SvelteKit / Vite framework-specific hunting** | **`references/11-modern-spa-hunting.md`** |
| **Supply chain — dep confusion, CI/CD injection, artifact stores, IaC, docker layers** | **`references/12-webapp-supply-chain.md`** |
| **Auth failures — JWT attacks, OAuth/OIDC/SAML, MFA bypass, session, password reset** | **`references/13-auth-failures-and-flows.md`** |
| **SQLi (error/UNION/boolean/OOB/stacked/second-order/WAF bypass) + NoSQL** | **`references/14-sqli-nosql-injections.md`** |
| **LDAP · XPath · SSTI · XXE · Supabase · Firebase · AI/ML unauth · more injections** | **`references/15-other-injections-and-unauth.md`** |
| **Full app crawl & surface mapping — auth model, roles, API schema, state machines** | **`references/16-app-crawl-and-map.md`** |

> **Load all relevant modules before responding.** For full-target analysis, load all files.

---

## 🚨 HARD RULE — read before doing anything else

**Enumerate every subdomain first. Crawl every live subdomain for its own JS
(don't assume it shares the apex domain's bundle). Beautify every minified file.
Read every single file completely, end to end. Never rely on grep/pattern-matching
alone, no matter how many files there are — this rule has no file-count exception.**

Grep finds `apikey` and `fetch(`. It does not tell you that a URL-upload feature
silently proxies through a server-side SSRF-able endpoint, or that a client-side role
flag never gets re-checked server-side. Every real finding comes from reading real
logic. See `references/01-js-discovery.md` Phase 0 for the per-subdomain crawl process.

---

## 🧠 JSRA Core Mindset

1. **JS is the attack surface map.** Every bundle, chunk, worker, source map = potential goldmine.
2. **Secrets are everywhere.** API keys, JWTs, OAuth tokens, internal URLs — devs forget JS is public.
3. **Every endpoint in JS is untested.** Hidden admin routes, internal APIs, staging endpoints.
4. **Auth logic lives client-side more than it should.** Role checks, feature flags, hardcoded user IDs.
5. **Dependencies are inherited attack surface.** One CVE in lodash or axios = your bug.
6. **Dynamic confirmation kills false positives.** Never report without a Selenium/fetch proof.
7. **Source maps are a cheat code.** `.js.map` files reveal original source, variable names, internal paths.

---

## 💰 Field-tested high-payout JS leaks (confirm live, then report)

- **Hardcoded OAuth *client* credentials** — `client_id`+`client_secret`, often a base64 `Authorization: Basic …` blob in a `*.min.js`. Mint a real token to prove it (non-theoretical):
  ```bash
  # use the Basic blob verbatim, or  echo -n "$CLIENT_ID:$CLIENT_SECRET" | base64
  curl -s -X POST "https://apigw.$TARGET/token" \
    -H "Authorization: Basic <BLOB>" -d "grant_type=client_credentials"
  # access_token returned = confirmed. The secret can't be rotated without breaking
  # prod → High/Critical. Then probe the gateway behind it with that token.
  ```
- **Analytics / feature-flag SDK write keys** (`client-…` for Statsig, Segment, LaunchDarkly, Amplitude). A *client* key is public by design — but if it accepts **event/log writes** it lets an attacker poison A/B tests and revenue dashboards:
  ```bash
  curl -s -X POST "https://api.<vendor>.com/v1/log_event" \
    -H "<VENDOR>-API-KEY: client-…" -H 'Content-Type: application/json' \
    -d '{"events":[{"eventName":"purchase_verified","value":5000,"user":{"userID":"x"}}]}'
  # HTTP 202 = injection works. Lead the report with data-integrity impact, NOT "leaked key".
  ```
- **Server SDK / secret keys** (`sk-…`, `secret-…`, service tokens) → hand to `jsmax` for exploitation.

---

## 🔄 Master Analysis Pipeline

```
INPUT (URL / .js file / HAR / domain)
        │
        ▼
JS DISCOVERY (waybackurls, gau, katana, regex scrape, source map check)
        │
        ▼
STATIC ANALYSIS (secrets/tokens/PII regex, endpoint extraction, auth logic review)
        │
        ▼
TOOL-ASSISTED SCAN (semgrep, trufflehog, retire.js, linkfinder, JSluice, eslint-security)
        │
        ▼
DEPENDENCY AUDIT (npm audit, retire.js, snyk, OSV lookup)
        │
        ▼
BUG-CLASS ANALYSIS
        │
        ├─► Secrets / PII / Token Leak
        ├─► Hidden / Misconfigured Endpoints
        ├─► DOM XSS (sources → sinks tracing)
        ├─► Prototype Pollution
        ├─► BAC / IDOR (hardcoded IDs, role bypass, object refs)
        ├─► Auth Logic Flaws (client-side checks, JWT misuse)
        └─► CVE in Dependencies
        │
        ▼
DYNAMIC CONFIRMATION (Selenium/Chromium/fetch scripts — eliminate false positives)
        │
        ▼
PoC BUILD (minimal repro script / HTTP request / browser automation)
        │
        ▼
REPORT (severity, CVSS, impact, steps, fix)
```

---

## ⚡ Quick Decision Router

| User Input | Load Module(s) |
|---|---|
| URL / domain given | `01-js-discovery` + `02-static-analysis` + `03-tool-scanning` |
| `.js` / `.ts` file uploaded | `02-static-analysis` + `03-tool-scanning` + `05-bug-classes` |
| HAR / Burp export | `02-static-analysis` + `05-bug-classes` |
| "find secrets / tokens / keys" | `02-static-analysis` + `03-tool-scanning` + `07-poc-and-fp-reduction` |
| "find endpoints" | `01-js-discovery` + `02-static-analysis` |
| "DOM XSS / prototype pollution" | `05-bug-classes` + `04-dynamic-analysis` |
| "IDOR / BAC / auth" | `05-bug-classes` + `04-dynamic-analysis` |
| "CVE / deps / retire.js" | `06-dependency-cves` + `03-tool-scanning` |
| Tool error / install issue | `08-tooling-and-errors` |
| "write PoC / confirm finding" | `07-poc-and-fp-reduction` + `04-dynamic-analysis` |
| "write report" | `09-report-template` |
| **Obfuscated / packed JS** | **`10-advanced-deobfuscation`** + `02-static-analysis` |
| **Next.js / Nuxt / Remix / SvelteKit / Vite target** | **`11-modern-spa-hunting`** + `02-static-analysis` |
| **WebSocket / SSE / GraphQL subscriptions** | `02-static-analysis` + **`04-dynamic-analysis`** (WS section) |
| **SSR state leak (`__NEXT_DATA__`, `__NUXT__`)** | **`11-modern-spa-hunting`** + `02-static-analysis` |
| **AI API key / OpenAI / Anthropic / HuggingFace** | `02-static-analysis` + `07-poc-and-fp-reduction` |
| **Service workers** | `01-js-discovery` (Phase 2b) + `02-static-analysis` |
| **Supply chain / dep confusion / CI-CD / IaC / docker / npm** | **`12-webapp-supply-chain`** |
| **JWT / OAuth / SAML / MFA / session / password reset bypass** | **`13-auth-failures-and-flows`** |
| **SQLi (any type) / NoSQL / WAF bypass / stacked / OOB** | **`14-sqli-nosql-injections`** |
| **LDAP / XPath / SSTI / XXE / Supabase / Firebase / AI-ML unauth** | **`15-other-injections-and-unauth`** |
| **App surface mapping / crawl / API schema / params / roles** | **`16-app-crawl-and-map`** |

---

## 🛠️ Self-Healing Protocol

When any tool, command, script, or install fails:
1. Parse stderr/stdout silently — identify root cause (missing dep, wrong flag, version mismatch, permission)
2. Auto-correct: fix the command, install the missing package, resolve the path issue
3. Retry automatically
4. If retry fails → offer 2 alternative approaches with fixed commands
5. Never tell the user "try again" — always hand them the fixed version
6. For Python scripts: catch exceptions, print diagnostic output, auto-fix imports

---

## 🎯 Integration with XRAT (XSS Hunter Agent)

- **JS endpoint discovery** from this skill feeds directly into XRAT's recon pipeline
- **DOM XSS sink/source findings** here should be handed off to XRAT for payload crafting
- **Prototype pollution** findings here → XRAT for gadget chaining to XSS
- **Token/secret leaks** are standalone findings — report directly
- **BAC/IDOR** findings are standalone — do not hand off to XRAT
