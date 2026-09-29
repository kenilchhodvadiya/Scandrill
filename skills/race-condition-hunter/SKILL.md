---
name: race-condition-hunter
description: Elite race condition / TOCTOU hunting skill for authorized bug bounty, pentests, and CTFs. ALWAYS activate for race condition, TOCTOU, time-of-check-time-of-use, double-spend, limit-overrun, single-packet attack, HTTP/2 parallel request, last-byte sync, Turbo Intruder race, "send group in parallel", coupon/voucher/gift-card reuse, referral/faucet/reward re-claim, withdrawal/transfer double-spend, refund race, 2FA/OTP race bypass, email/phone verification race, invitation/seat/quota overrun, signup email-uniqueness collision, order/inventory oversell, rate-limit bypass via race, non-atomic check-then-write, "test for race condition on $target", "race these requests", or ANY request to find/exploit concurrency bugs where a "once-only" guard can be beaten by firing N requests simultaneously. Drives the full kill chain — candidate mapping → single-packet fire → over-limit detection → impact proof → report. P2/P3 focus, kills theoretical no-gain races upfront.
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


# Race Condition Hunter

## Overview

**Core principle:** A check and its use are not atomic. Fire N requests in parallel so several pass the CHECK before any completes the ACT — slipping past a "once-only" guard.

```
Non-atomic operation:
  1. CHECK (read state)   ← all N attackers enter here
  2. ...gap...            ← the race window
  3. ACT  (modify state)  ← N writes collide, guard beaten
```

The modern, reliable way to hit that window is the **single-packet attack** (James Kettle, "Smashing the State Machine", 2023) — deliver 20–50 requests to arrive within microseconds, eliminating network jitter.

## When to Use

Activate when an endpoint enforces a **limit, uniqueness, or one-time guard** through a read-then-write that isn't wrapped in a DB transaction / atomic update / lock.

**Symptoms that scream "race me":**
- "This code can only be used once" / one-time coupon, voucher, gift card
- "One reward per account" — referral, faucet, daily claim, signup bonus
- Balance check before withdraw / transfer / spend (double-spend)
- Uniqueness check before insert (email, username, seat, invite)
- State toggle (enable/disable 2FA, accept/decline invite, publish/moderate)
- Rate limits and OTP attempt caps (fire before the counter increments)

**When NOT to bother:** a race that produces no tangible over-limit gain is **N/A**. No doubled balance, no extra redemption, no quota breach → drop it. Kill theoretical races upfront.

## Kill Chain

1. **Map candidates** — state-changing endpoints with a check+write (see Target Tiers).
2. **Baseline** — send the op once, confirm it *correctly* succeeds once.
3. **Fire** — 20–50 identical requests via single-packet attack (see PoC Templates).
4. **Detect over-limit** — more than one success / doubled counter / quota exceeded.
5. **Prove impact** — show the over-limit *result* (negative balance, N redemptions), 3+ reps.
6. **Report** — impact-first, with the concurrency level and final state.

## Target Tiers (follow the money / the "once" guard)

**Tier 1 — Critical (direct financial):**
`POST /coupon/redeem` · `/refund` · `/withdraw` · `/transfer` · gift-card redeem · reward-points spend · referral/faucet claim · flash-sale / limited-inventory buy

**Tier 2 — High (privilege / access):**
`/accept-invitation` (seat limit) · team-member add · email/OTP verify (single-use token) · password-reset token use · `PATCH /2fa/disable` (old/new secret window) · account merge/link · trial activation

**Tier 3 — Medium (workflow integrity):**
order status transitions · KYC-approval→unlock · publish→moderation bypass · duplicate account creation · leaderboard/score submit · rate-limit bypass

## The Technique

**HTTP/2 single-packet attack (preferred, jitter-free):** open many streams on one connection, hold back the final byte of each, release all last bytes in one TCP packet → server processes near-simultaneously.
- **Burp Repeater:** add requests to a group → **"Send group in parallel (single-packet attack)"**.
- **Turbo Intruder:** `engine=Engine.BURP2` with `gate`-synced requests (skeletons in references).

**HTTP/1.1 last-byte sync:** send all requests holding back the final byte, then release together. Turbo Intruder handles this; `wrk` works for crude HTTP/1.1 flooding.

**Tuning:** warm the connection first. Fetch a fresh single-use anti-CSRF token per request only if the endpoint requires it — a stale/shared token can itself throttle you.

## Detection

Run 20–50 concurrent copies of a "should-succeed-once" operation. **Race confirmed if you see:**
- Multiple `200`/success where exactly one was allowed
- Two+ resources with the same unique field (email, order id)
- A counter incremented more than the number of *logical* actions
- Balance credited twice / debited past zero (negative)

Always compare against a **sequential baseline** that correctly allows only one.

## Common Recipes

- **Coupon stacking:** 20× `POST /redeem {code}` → 20 stacked discounts → negative price.
- **Withdraw double-spend:** balance 100, 5× `POST /withdraw {amount:100}` → several clear before balance reads zero.
- **Refund → infinite credit:** buy $10, fire 30× `/refund`, some succeed → $50 credited. Stop at a program-acceptable PoC; never keep real funds.
- **Email-uniqueness collision:** N× `/signup {email}` → uniqueness check skipped → duplicate accounts → collision/ATO primitives.
- **2FA race bypass:** submit OTP and `/2fa/disable` concurrently → one reads "enabled" and rejects, the other disables; retry passes.
- **Invitation race:** accept + decline simultaneously → inconsistent state (member but not listed).
- **Oversell:** place order while inventory check runs → reserve stock that doesn't exist.

## Cross-Endpoint & Advanced Races

- **Multi-step (state-machine collision):** race the endpoint that *sets* state while the endpoint that *reads* it is mid-flight (e.g. re-apply discount during checkout complete → used twice). Map which endpoint reads state another sets, then collide them.
- **State-collision → RCE:** "create if not exists" + "run hook on create" → race two creates so a hook fires before authz completes. Upload race: file uploaded → scan starts → second request moves it public before scan finishes.

## Mobile API Races

Same API-level attack: hit the intercepted endpoint with the asyncio/Turbo scripts. Extras: Burp Repeater parallel tabs; ADB launch app instances simultaneously; StoreKit/IAP UI race (rapid purchase-tap); deep-link rapid-open race.

## Source-Code Smell (SAST hint)

Vulnerable = read → conditional → write with **no** transaction/lock/atomic update:
```js
const bal = await db.query('SELECT balance ... WHERE id=?');   // CHECK
if (bal >= amount) await db.query('UPDATE ... balance-? ...');  // USE — gap
```
Secure = single atomic statement or row lock:
```sql
UPDATE balances SET amount=amount-? WHERE user_id=? AND amount>=?;  -- rows==0 → reject
-- or: SELECT ... FOR UPDATE inside a transaction
-- Django: User.objects.filter(id=uid, credits__gte=cost).update(credits=F('credits')-cost)
```

## Proof-of-Impact Bar & Severity

Show the **over-limit result**, not just "many 200s": two redemptions, doubled balance, N verification rewards, quota exceeded, negative balance.
- Financial/asset over-limit = **High**, CVSS ~7.5 (note `AC:H` — attack complexity high).
- Reproduce **3+ times**; capture the concurrency level, hold/gate details, and before/after state.
- No tangible over-limit gain = **N/A**. Don't submit it.

## Real Paid Examples (HackerOne)

| Program | Bug | Payout |
|---|---|---|
| Cosmos | faucet race via starport | $5k |
| Tools-for-Humanity | race bypasses verification check | $3k |
| InnoGames | race in email activation → infinite diamonds | $2k |
| Shopify | race on create Location (quota) | $500 |
| Razer | race in OAuth 2.0 flow | $250 |
| Helium / HackerOne | transfer-credits race / race joining CTF group | — |

## Common Mistakes

| Mistake | Fix |
|---|---|
| Requests spaced by ms (browser/normal Repeater) | Use single-packet attack; jitter kills the window |
| Reporting "20× 200 OK" with no state change | Prove the over-limit *result* |
| Shared/stale CSRF token throttles the burst | Fresh single-use token per request only if required |
| No sequential baseline | Always show it correctly allows one when serialized |
| Keeping real refunds/withdrawals | Minimal-dollar PoC; reverse it; never profit |

## PoC Templates

Ready-to-paste Turbo Intruder skeletons (gated single-packet + last-byte), Python `asyncio`/`httpx` HTTP/2 racer, threading racer, and a `curl`/`xargs` one-liner live in **references/poc-templates.md**. Tooling: Turbo Intruder, Burp Repeater "Send in parallel", `race-the-web`, `smuggler` (h2 frame races).

## Cross-Skill Knowledge References (global — load when relevant)

- `~/.claude/skills/js-recon-agent/references/13-auth-failures-and-flows.md` — Auth failures: JWT attacks, OAuth/OIDC/SAML, MFA bypass, password reset, session
- `~/.claude/skills/js-recon-agent/references/17-authenticated-testing-checklist.md` — **Commonly missed authenticated checks: subscription bypass, async job result IDOR, session invalidation, API key scope escalation, WebSocket message auth, mass assignment, invitation abuse, multi-tenant trust, cookie-strip bypass. Race-condition-specific: also test bulk IDOR arrays and async job endpoints for race windows.**
