# 02 — Static Analysis

## Goal
Deep-read JS files as a top 1% JS developer. Find secrets, PII, hidden endpoints, auth logic, dangerous patterns.

---

## Master Regex Pattern Set

```python
# scripts/static_scan.py
import re, os, sys, json
from pathlib import Path

TARGET_DIR = sys.argv[1] if len(sys.argv) > 1 else "js_files"

PATTERNS = {
    # === SECRETS & TOKENS ===
    "AWS_Access_Key":       r'AKIA[0-9A-Z]{16}',
    "AWS_Secret_Key":       r'(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key["\s:=]+[A-Za-z0-9/+=]{40}',
    "AWS_Session_Token":    r'AWS_SESSION_TOKEN["\s:=]+[A-Za-z0-9/+=]{100,}',
    "GCP_API_Key":          r'AIza[0-9A-Za-z\-_]{35}',
    "GCP_Service_Account":  r'"type"\s*:\s*"service_account"',
    "Firebase_Key":         r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    "Firebase_Config":      r'firebaseConfig\s*=\s*\{[^}]+apiKey[^}]+\}',
    "GitHub_Token":         r'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|ghs_[A-Za-z0-9]{36}',
    "Slack_Token":          r'xox[baprs]-[0-9A-Za-z\-]{10,72}',
    "Slack_Webhook":        r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+',
    "Stripe_Key":           r'sk_live_[0-9a-zA-Z]{24,}|pk_live_[0-9a-zA-Z]{24,}',
    "Stripe_Test_Key":      r'sk_test_[0-9a-zA-Z]{24,}',
    "Twilio_SID":           r'AC[a-zA-Z0-9]{32}',
    "SendGrid_Key":         r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}',
    "JWT_Token":            r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    "Bearer_Token":         r'(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}',
    "Basic_Auth":           r'(?i)(?:Authorization|auth)\s*[:=]\s*["\']?Basic\s+[A-Za-z0-9+/=]{10,}',
    "Password_Hardcoded":   r'(?i)(?:password|passwd|pwd|secret)\s*[:=]\s*["\'][^"\']{4,}["\']',
    "API_Key_Generic":      r'(?i)(?:api[_\-]?key|apikey|api_secret)\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']',
    "Private_Key_PEM":      r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
    "OAuth_Token":          r'(?i)(?:access_token|oauth_token)\s*[:=]\s*["\'][A-Za-z0-9_\-\.]{20,}["\']',
    "Google_OAuth":         r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',

    # === AI / LLM API KEYS (2024-2025 high-value) ===
    "OpenAI_Key":           r'sk-[A-Za-z0-9]{48}|sk-proj-[A-Za-z0-9_\-]{48,}|sk-svcacct-[A-Za-z0-9_\-]{48,}',
    "Anthropic_Key":        r'sk-ant-(?:api|admin)?[A-Za-z0-9\-_]{90,}',
    "HuggingFace_Token":    r'hf_[A-Za-z0-9]{34,}',
    "Replicate_Token":      r'r8_[A-Za-z0-9]{40}',
    "Cohere_Key":           r'[A-Za-z0-9]{40}(?=.*cohere)',
    "Mistral_Key":          r'(?i)mistral[_\-]?(?:api[_\-]?)?key["\s:=]+[A-Za-z0-9]{32,}',
    "OpenRouter_Key":       r'sk-or-[A-Za-z0-9\-_]{40,}',
    "Groq_Key":             r'gsk_[A-Za-z0-9]{52}',
    "Together_AI_Key":      r'(?i)together[_\-]?(?:api[_\-]?)?key["\s:=]+[A-Za-z0-9]{40,}',
    "ElevenLabs_Key":       r'(?i)xi[_\-]?api[_\-]?key["\s:=]+[A-Za-z0-9]{32,}',

    # === SAAS / PLATFORM TOKENS ===
    "Shopify_Token":        r'shpss_[A-Za-z0-9]{32}|shpat_[A-Za-z0-9]{32}|shpca_[A-Za-z0-9]{32}|shppa_[A-Za-z0-9]{32}',
    "Vercel_Token":         r'vc_[A-Za-z0-9]{32,}',
    "Netlify_Token":        r'(?i)netlify[_\-]?(?:api[_\-]?)?(?:token|key)["\s:=]+[A-Za-z0-9\-_]{32,}',
    "Datadog_API_Key":      r'(?i)(?:dd_api_key|datadog)["\s:=]+[A-Za-z0-9]{32}',
    "New_Relic_Key":        r'NRAK-[A-Za-z0-9]{27}',
    "Intercom_Token":       r'(?i)intercom[_\-]?(?:access[_\-]?)?token["\s:=]+[A-Za-z0-9]{40,}',
    "Zendesk_Token":        r'(?i)zendesk[_\-]?(?:api[_\-]?)?token["\s:=]+[A-Za-z0-9\/]{40,}',
    "Supabase_Key":         r'(?i)supabase[_\-]?(?:anon|service)[_\-]?key["\s:=]+[A-Za-z0-9\._\-]{100,}',
    "Mapbox_Token":         r'sk\.[A-Za-z0-9]{80,}|pk\.[A-Za-z0-9]{80,}',
    "Algolia_Admin_Key":    r'(?i)algolia[_\-]?(?:admin[_\-]?)?(?:api[_\-]?)?key["\s:=]+[A-Za-z0-9]{32}',
    "LaunchDarkly_SDK":     r'(?i)launchdarkly[_\-]?(?:sdk[_\-]?)?(?:key|token)["\s:=]+[A-Za-z0-9\-_]{40,}',
    "Segment_Write_Key":    r'(?i)(?:segment|analytics)[_\-]?(?:write[_\-]?)?key["\s:=]+[A-Za-z0-9]{20,}',
    "Amplitude_Key":        r'(?i)amplitude[_\-]?(?:api[_\-]?)?key["\s:=]+[A-Za-z0-9]{32}',
    "Mixpanel_Token":       r'(?i)mixpanel[_\-]?(?:api[_\-]?)?(?:token|secret)["\s:=]+[A-Za-z0-9]{32}',
    "Sentry_DSN":           r'https://[0-9a-f]{32}@[a-z0-9\.]+\.ingest\.sentry\.io/[0-9]+',
    "Pusher_Key":           r'(?i)pusher[_\-]?(?:app[_\-]?)?(?:key|secret)["\s:=]+[A-Za-z0-9]{20,}',

    # === PII ===
    "Email_Address":        r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b',
    "Phone_Number":         r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
    "SSN":                  r'\b\d{3}-\d{2}-\d{4}\b',
    "Credit_Card":          r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
    "IP_Address_Private":   r'\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b',

    # === ENDPOINTS & URLS ===
    "Internal_URL":         r'https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2[0-9]|3[01])\.\d+\.\d+)[^\s"\']*',
    "Staging_URL":          r'https?://(?:staging|dev|test|uat|sandbox|internal|admin|api-dev)[.\-][^\s"\']{5,}',
    "S3_Bucket":            r's3://[a-z0-9.\-]{3,63}|https?://[a-z0-9.\-]{3,63}\.s3(?:[\-\.][a-z0-9\-]+)?\.amazonaws\.com',
    "API_Endpoint":         r'(?:fetch|axios|xhr|http(?:Get|Post|Put|Delete|Patch)|request)\s*\(["\'][^"\']{10,}["\']',
    "GraphQL_Endpoint":     r'/graphql|/__graphql|/api/graphql|/gql',
    "GraphQL_WS":           r'wss?://[^\s"\']+(?:graphql|subscriptions|gql)|new\s+(?:Subscription|WebSocket)\s*\(["\'][^"\']*graphql',
    "WebSocket_Endpoint":   r'new\s+WebSocket\s*\(["\']wss?://[^\s"\']+["\']|wss?://[^\s"\']{5,}',
    "SSE_Endpoint":         r'new\s+EventSource\s*\(["\'][^"\']+["\']|["\'](?:/sse|/events|/stream|/subscribe)["\']',
    "Admin_Route":          r'["\'/](?:admin|dashboard|internal|manage|superuser|staff|root)["\'/]',
    "Debug_Endpoint":       r'["\'/](?:debug|test|dev|trace|status|health|metrics|actuator)["\'/]',

    # === SSR STATE LEAKS (Next.js / Nuxt / Remix) ===
    "Next_Data_Blob":       r'__NEXT_DATA__',
    "Nuxt_State":           r'window\.__NUXT__\s*=',
    "Remix_Context":        r'window\.__remixContext\s*=',
    "Initial_State_Blob":   r'window\.(?:initialState|bootstrapData|APP_STATE|__APP_STATE__)\s*=',

    # === AUTH LOGIC ===
    "Role_Check_Client":    r'(?i)(?:isAdmin|is_admin|role\s*===?\s*["\']admin|userRole|checkPermission|hasAccess|isAuthorized)',
    "JWT_Decode_Client":    r'(?i)(?:atob|jwt\.decode|parseJwt|decodeToken)\s*\(',
    "Feature_Flag":         r'(?i)(?:featureFlag|feature_flag|isEnabled|canAccess|betaUser)',
    "Hardcoded_User_ID":    r'(?i)(?:userId|user_id|account_id)\s*[:=]\s*["\'][0-9a-f\-]{5,}["\']',
    "Skip_Auth":            r'(?i)(?:skipAuth|bypassAuth|noAuth|skip_authentication|auth\s*=\s*false)',
    "Next_Middleware_Skip": r'x-middleware-subrequest',  # CVE-2025-29927 header

    # === DANGEROUS PATTERNS (DOM XSS / Code Exec) ===
    "innerHTML_Sink":               r'\.innerHTML\s*[+]?=\s*',
    "outerHTML_Sink":               r'\.outerHTML\s*[+]?=\s*',
    "insertAdjacentHTML":           r'\.insertAdjacentHTML\s*\(',
    "dangerouslySetInnerHTML":      r'dangerouslySetInnerHTML\s*=\s*\{',
    "v_html_directive":             r'v-html\s*=\s*["\']',
    "Angular_bypassSecurity":       r'bypassSecurityTrust(?:Html|Url|Style|Script|ResourceUrl)\s*\(',
    "document_write":               r'document\.write(?:ln)?\s*\(',
    "eval_call":                    r'\beval\s*\(',
    "Function_constructor":         r'new\s+Function\s*\(',
    "setTimeout_string":            r'setTimeout\s*\(\s*["\']',
    "setInterval_string":           r'setInterval\s*\(\s*["\']',
    "location_hash_sink":           r'location\.hash|location\.search|location\.href\s*=',
    "postMessage_no_origin":        r'addEventListener\s*\(\s*["\']message["\'](?![^{]*\.origin)',
    "prototype_pollution":          r'__proto__|constructor\[[\'""]prototype[\'""]|Object\.assign\s*\(\s*\w+\.prototype',
    "jQuery_html_sink":             r'\$\([^)]+\)\.html\s*\((?!null|""|\'\')',
    "window_location_assign":       r'window\.location\.(?:assign|replace)\s*\(\s*(?!["\']/)',

    # === OBFUSCATION RED FLAGS (deobfuscate before analysis) ===
    "Obfuscator_IO":        r'eval\s*\(function\s*\(p,a,c,k,e,d\)',
    "Hex_String_Encoding":  r'\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}',
    "String_Array_Shift":   r'_0x[a-f0-9]{4,}\[\'shift\'\]\s*\(\s*\)',
    "Unicode_Escape":       r'\\u[0-9a-fA-F]{4}\\u[0-9a-fA-F]{4}\\u[0-9a-fA-F]{4}',

    # === ENCRYPTION / CRYPTO MISUSE ===
    "MD5_Usage":            r'(?i)md5\s*\(',
    "Weak_Random":          r'Math\.random\s*\(',
    "Hardcoded_IV":         r'(?i)(?:iv|initialization_vector)\s*[:=]\s*["\'][A-Fa-f0-9]{16,}["\']',
    "ECB_Mode":             r'(?i)AES-ECB|mode:\s*CryptoJS\.mode\.ECB',
    "Base64_Encoded_Secret":r'(?i)(?:secret|key|token|password)\s*[:=]\s*["\'][A-Za-z0-9+/]{40,}={0,2}["\']',
    "Hardcoded_HMAC_Secret":r'(?i)(?:hmac|signing)[_\-]?secret["\s:=]+["\'][A-Za-z0-9_\-\.]{20,}["\']',
}

findings = []

for js_file in Path(TARGET_DIR).rglob("*.js"):
    try:
        content = js_file.read_text(errors='ignore')
        lines = content.splitlines()
        for pattern_name, pattern in PATTERNS.items():
            for i, line in enumerate(lines, 1):
                matches = re.finditer(pattern, line)
                for match in matches:
                    findings.append({
                        "file": str(js_file),
                        "line": i,
                        "pattern": pattern_name,
                        "match": match.group()[:120],
                        "context": line.strip()[:200]
                    })
    except Exception as e:
        print(f"[ERR] {js_file}: {e}")

# Group by pattern type
by_type = {}
for f in findings:
    by_type.setdefault(f['pattern'], []).append(f)

print(f"\n{'='*60}")
print(f"[JSRA STATIC SCAN] {len(findings)} findings across {len(by_type)} categories")
print(f"{'='*60}")
for ptype, items in sorted(by_type.items(), key=lambda x: -len(x[1])):
    print(f"\n[{ptype}] — {len(items)} hit(s)")
    for item in items[:5]:  # cap at 5 per type in stdout
        print(f"  File: {item['file']}:{item['line']}")
        print(f"  Match: {item['match']}")
        print(f"  Context: {item['context'][:100]}")

with open("static_findings.json", "w") as f:
    json.dump(findings, f, indent=2)
print(f"\n[+] Full results saved to static_findings.json")
```

```bash
python scripts/static_scan.py js_files/
```

---

## Endpoint Extraction (Deep)

```bash
# LinkFinder — extract endpoints from JS
python3 linkfinder.py -i js_files/ -o endpoints.html
python3 linkfinder.py -i https://target.com -d -o endpoints_live.html

# JSluice — semantic endpoint extraction
jsluice urls js_files/*.js | tee jsluice_endpoints.txt
jsluice secrets js_files/*.js | tee jsluice_secrets.txt

# Grep for API paths
grep -rEoh '"/api/[^"]{3,}"|'"'/api/[^']{3,}'" js_files/ | sort -u > api_paths.txt

# Find fetch/axios/XHR calls with full URLs
grep -rE "(fetch|axios\.(get|post|put|delete)|XMLHttpRequest)\(['\"]https?://" js_files/ | head -50
```

---

## Auth Logic Review Checklist

When reviewing auth patterns manually look for:

1. **Client-side role enforcement** — `if (user.role === 'admin')` — always bypassable
2. **JWT claims used client-side** — decode JWT in browser, check if claims drive UI without server verification
3. **Feature flag bypasses** — `localStorage.setItem('admin', true)`
4. **Object reference patterns** — `/api/user/{id}/data` — is `id` validated server-side?
5. **Hardcoded object IDs** — UUIDs or numeric IDs in JS source that belong to other users

---

## Source Map Intelligence Extraction

```bash
# If .map files recovered, extract original source
# Source maps contain: sources[], sourcesContent[], mappings
python3 -c "
import json, os, sys
map_file = sys.argv[1]
with open(map_file) as f:
    sm = json.load(f)
os.makedirs('recovered', exist_ok=True)
for i, (src, content) in enumerate(zip(sm.get('sources',[]), sm.get('sourcesContent',[]))):
    if content:
        fname = 'recovered/' + src.replace('../','').replace('/','_').lstrip('_')
        os.makedirs(os.path.dirname(fname) or '.', exist_ok=True)
        with open(fname,'w') as out:
            out.write(content)
        print(f'[+] {fname}')
" main.js.map
```

---

## SSR State Analysis (Next.js / Nuxt / Remix — HIGH VALUE, usually skipped)

SSR frameworks embed server-side data verbatim in HTML. This is NOT visible in `.js` files —
it's in the HTML page source itself. One curl can reveal tokens, user PII, internal API URLs.

```bash
# Pull raw HTML and extract state blobs
curl -sL "https://target.com/" > /tmp/page.html

# Next.js — __NEXT_DATA__ contains: props, pageProps, buildId, internal API data
python3 - <<'EOF'
import re, json, sys
html = open('/tmp/page.html').read()
m = re.search(r'<script[^>]*id=["\']__NEXT_DATA__["\'][^>]*>(.+?)</script>', html, re.DOTALL)
if m:
    data = json.loads(m.group(1))
    print(json.dumps(data, indent=2))
    # Hunt for: tokens, user objects, API base URLs, env vars leaked into props
    txt = json.dumps(data)
    for kw in ['token','apiKey','secret','password','Authorization','BASE_URL','NEXT_PUBLIC_']:
        if kw.lower() in txt.lower():
            print(f"[!!] KEYWORD HIT: {kw}")
EOF

# Nuxt — window.__NUXT__ often contains vuex store state including user session
python3 -c "
import re, json
html = open('/tmp/page.html').read()
m = re.search(r'window\.__NUXT__\s*=\s*(\{.+?\})\s*;', html, re.DOTALL)
if m:
    print('[NUXT STATE]', m.group(1)[:2000])
"

# Generic: look for any window.* = {...} assignments in HTML inline scripts
grep -oP 'window\.\w+\s*=\s*\{.{20,200}\}' /tmp/page.html | head -20
```

**What to look for in SSR state:**
- `props.pageProps.user` — full user object (PII, role, plan tier)
- `props.pageProps.token` / `props.pageProps.accessToken` — usable auth token
- Internal API base URL (`apiUrl`, `backendUrl`, `internalApiBase`)
- Feature flags resolved server-side (shows all flags, including disabled features)
- `NEXT_PUBLIC_*` env vars (these are intentionally public, but check for accidental secret leaks)
- `buildId` — fingerprints Next.js version (useful for CVE-2025-29927 check)

---

## WebSocket & SSE Endpoint Analysis

WebSocket endpoints are routinely skipped. They often carry the same or richer data as REST
endpoints but skip HTTP middleware (auth, rate-limit, WAF) that was only wired up for HTTP.

```bash
# Find WebSocket endpoints in JS
grep -rEn 'new\s+WebSocket\s*\(["\']wss?://[^\s"\']+["\']' beautified/ | \
  grep -oE 'wss?://[^\s"\']+' | sort -u > ws_endpoints.txt

# Find via string construction (dynamic WS URLs)
grep -rEn '(wsUrl|wsEndpoint|socketUrl|SOCKET_URL|ws_url)\s*[:=]\s*' beautified/ | head -20

# SSE / EventSource
grep -rEn 'new\s+EventSource\s*\(' beautified/ | head -10

# Test WebSocket without auth (wscat / websocat)
# Install: npm install -g wscat  or  cargo install websocat
wscat -c wss://target.com/ws --no-check              # no auth header
wscat -c wss://target.com/ws/events?token=INVALID    # test token validation
# websocat alternative: websocat "wss://target.com/ws"

# Test if WS accepts different origins
wscat -c wss://target.com/ws \
  --header "Origin: https://evil.com" \
  --header "Host: target.com"
# If connects → CORS on WS missing → cross-origin WS exfil

# Subscribe probe (GraphQL WS / socket.io style)
echo '{"type":"connection_init","payload":{}}' | wscat -c wss://target.com/graphql --no-check
echo '{"type":"subscribe","id":"1","payload":{"query":"{users{id email}}"}}' | wscat -c wss://target.com/graphql
```

---

## Advanced Static Extraction (v2 — creative additions)

> These run **alongside** the full read, never instead of it. They surface leads faster;
> the bug still comes from reading the logic.

### Modern semantic tool sweep (fewer FPs than raw regex)

```bash
# jsluice — AST-based, understands JS structure (far fewer FPs than regex)
jsluice urls    beautified/*.js | jq -r '.url' | sort -u > jsluice_urls.txt
jsluice secrets beautified/*.js | tee jsluice_secrets.json

# mantra — fast API-key hunter over a URL list
cat js.txt | mantra

# xnLinkFinder — endpoints + params, scales to huge inputs
xnLinkFinder -i beautified/ -sf target.com -o xnlf_endpoints.txt -op xnlf_params.txt

# nuclei exposure templates straight at the JS URLs
nuclei -l js.txt -t http/exposures/ -t http/miscellaneous/ -silent

# trufflehog — VERIFIED-only (validates against issuer API → kills FPs at source)
trufflehog filesystem js_files/ --only-verified --json | jq -r '.DetectorName+" "+.Raw'

# retire.js — bundled-library CVEs
retire --js --jspath beautified/ --outputformat json
```

### SPA router-table extraction — hidden admin/beta routes the nav never links

```bash
# React Router / Vue Router / Angular route configs live in the bundle. Pull them:
grep -oE '(path|route)\s*:\s*["'\''][^"'\'']+["'\'']' beautified/*.js | sort -u
grep -oE '\{[^}]*path:[^}]*component:[^}]*\}' beautified/*.js | head -50
grep -oE 'loadChildren|canActivate|PrivateRoute|RequireAuth|data:\s*\{[^}]*role' beautified/*.js
# Then VISIT every route directly. Client-side guards (canActivate / PrivateRoute) do NOT
# protect the API behind them — /admin, /internal, /beta, /debug, /impersonate are the gold.
```

### Feature-flag discovery — flip to unlock ungated functionality

```bash
grep -oiE '(featureFlag|feature_flag|isEnabled|flags?\[["'\''][^"'\'']+|launchdarkly|split\.io|optimizely|growthbook)' beautified/*.js | sort -u
# Flags evaluated CLIENT-SIDE can be forced (localStorage / ?flag= / cookie / console edit).
# If flipping one reveals an endpoint that isn't ALSO gated server-side → BAC/BFLA.
```

### Webpack lazy-chunk enumeration — chunks no crawler triggered

```bash
# The runtime bootstrap holds the chunkId->hash map. Extract it, rebuild every chunk URL.
grep -oE '\{[0-9]+:"[0-9a-f]{6,}"[,0-9a-f:"]*\}' beautified/*runtime*.js beautified/*.js | head
# Reconstruct  <publicPath>/<chunkId>.<hash>.js  and fetch each — many are lazy admin/settings bundles
# that only load after an action a crawler never performed.
```

### Historical version-diffing — secrets "removed" but still live server-side

```bash
# Pull OLD copies of the SAME bundle path from Wayback and diff against live.
echo "https://$HOST" | waybackurls | grep -E 'main\.[a-f0-9]+\.js' | sort -u > old_bundles.txt
diff <(js-beautify old_main.js) <(js-beautify live_main.js) \
  | grep -E '^[<>].*(api|key|token|secret|/internal|/admin)'
# An endpoint or secret deleted from the CURRENT bundle is frequently STILL LIVE on the server.
```
