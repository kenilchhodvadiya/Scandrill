# 16 — Application Crawl & Complete Surface Mapping

## Goal
Systematically map every attack surface of a web application before hunting.
A partial map = missed bugs. This methodology produces a complete picture:
endpoints, auth model, user roles, API schema, parameters, state machines, and tech stack.

---

## Phase 0 — Pre-Crawl Fingerprinting (Know Before You Crawl)

```bash
T="target.com"

# Tech stack identification (drives everything else)
httpx -u "https://$T" -title -tech-detect -server -status-code -cdn -cname -ip -silent -json | \
  python3 -m json.tool

# Wappalyzer fingerprint from browser or CLI
wappalyze "https://$T" 2>/dev/null | jq '.[].name'

# Response headers reveal framework/server/security posture
curl -sI "https://$T" | grep -iE 'server|x-powered-by|cf-ray|via|x-aspnet|x-amz|set-cookie'

# robots.txt + sitemap.xml → admin paths, hidden endpoints
curl -s "https://$T/robots.txt" | grep -v '#'
curl -s "https://$T/sitemap.xml" | grep -oE 'https://[^<]*' | sort -u > sitemap_urls.txt
curl -s "https://$T/sitemap_index.xml" | grep -oE 'https://[^<]*\.xml' | while read u; do
  curl -s "$u" | grep -oE 'https://[^<]*' >> sitemap_urls.txt
done

# Security.txt (often reveals responsible disclosure process + org structure)
curl -s "https://$T/.well-known/security.txt"

# OIDC / OAuth discovery
curl -s "https://$T/.well-known/openid-configuration" | python3 -m json.tool
curl -s "https://$T/.well-known/oauth-authorization-server" | python3 -m json.tool

# CDN / origin detection
dig "$T" +short | head -5
curl -sI "https://$T" | grep -i 'cf-ray\|x-cache\|via\|x-amz-cf'
```

---

## Phase 1 — Passive URL Collection (Zero Touch)

```bash
# Multi-source historical URL collection
echo "$T" | waybackurls | anew all_urls.txt
echo "$T" | gau --subs --threads 5 | anew all_urls.txt
waymore -i "$T" -mode U -oU waymore.txt 2>/dev/null && cat waymore.txt | anew all_urls.txt

# URLScan.io (JSON API — no auth needed for public results)
curl -s "https://urlscan.io/api/v1/search/?q=domain:$T&size=500" | \
  jq -r '.results[].page.url' | anew all_urls.txt

# Common Crawl index (high volume of historical URLs)
python3 - <<'PYEOF'
import requests, sys
TARGET = "target.com"
INDEX = "CC-MAIN-2024-10"  # use latest index
url = f"http://index.commoncrawl.org/{INDEX}-index?url={TARGET}/*&output=json&limit=5000"
for line in requests.get(url, timeout=30, stream=True).iter_lines():
    import json
    try: print(json.loads(line)['url'])
    except: pass
PYEOF | anew all_urls.txt

# AlienVault OTX
curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/$T/url_list?limit=500&page=1" | \
  jq -r '.url_list[].url' 2>/dev/null | anew all_urls.txt

# Filter and categorize
cat all_urls.txt | grep '=' | uro > params_urls.txt                # parameterized URLs
cat all_urls.txt | grep -iE '\.js(\?|$)' | uro > js_urls.txt      # JS files
cat all_urls.txt | grep -iE '\.json(\?|$)' | uro > json_urls.txt  # JSON endpoints
cat all_urls.txt | grep -iE '\.xml|\.yaml|\.yml|\.toml|\.env|\.config' > config_urls.txt
cat all_urls.txt | grep -iE 'api|graphql|v1|v2|v3|rest|service' > api_urls.txt

echo "[SUMMARY]"
echo "Total URLs: $(wc -l < all_urls.txt)"
echo "With params: $(wc -l < params_urls.txt)"
echo "JS files: $(wc -l < js_urls.txt)"
echo "API endpoints: $(wc -l < api_urls.txt)"
```

---

## Phase 2 — Active Crawl (All Crawlers, Every Host)

```bash
# Run all crawlers per host — each finds different things
for HOST in $(cat live_hosts.txt); do
  echo "[CRAWLING] $HOST"
  
  # katana: best for SPA/Next.js/React — follows JS dynamic routes
  katana -u "https://$HOST" -jc -jsl -d 5 -kf all -aff -silent 2>/dev/null | anew all_urls.txt
  
  # gospider: follows links, discovers subdomains  
  gospider -s "https://$HOST" -d 3 --js -o gospider_out/ 2>/dev/null
  cat gospider_out/*.txt 2>/dev/null | anew all_urls.txt
  
  # hakrawler: fast, good for API endpoints
  hakrawler -url "https://$HOST" -d 3 -subs -js -forms 2>/dev/null | anew all_urls.txt
  
  # cariddi: intensive recursive extraction
  cariddi -s "https://$HOST" -intensive -e -ef js,json,xml,txt,env 2>/dev/null | anew all_urls.txt
  
  # feroxbuster: directory brute force (finds paths not linked from anywhere)
  feroxbuster -u "https://$HOST" -w /usr/share/wordlists/raft-medium-directories.txt \
    -t 50 -q --no-state -o "ferox_$HOST.txt" 2>/dev/null
  cat "ferox_$HOST.txt" | grep "200\|204\|301\|302\|307\|401\|403" | awk '{print $NF}' | anew all_urls.txt
done
```

---

## Phase 3 — Manual Browser Crawl (Mandatory — Tools Miss This)

The most important phase. Tools miss: auth-gated routes, lazy chunks, modal content,
multi-step flows, feature-flag-gated UI, SSE/WebSocket endpoints, and anything requiring clicks.

```
SETUP:
1. Burp Suite (or mitmproxy) as proxy — intercept ALL traffic
2. Enable these Burp extensions passively: JS Miner, Param Miner, JS Link Finder
3. Open browser, set proxy to Burp
4. Navigate to target

CRAWL SEQUENCE (follow this order):
1. Landing page → note all external script/style resources (CDN, third parties)
2. Register / create account (signup flow = multi-step, click through each step)
3. Log in → note auth mechanism (cookie? JWT in header? localStorage?)
4. HOME / DASHBOARD:
   - Click every navigation item
   - Every sidebar link, every tab, every modal trigger
   - Check DevTools Network tab → note every XHR/fetch call as you click
5. SETTINGS / PROFILE:
   - Change every field type (text, file, select, toggle)
   - Note any file upload endpoints
   - Note any email-change / password-change flows
6. MAIN FEATURES (whatever the app does):
   - Go through every workflow end-to-end
   - Multiple-step wizards → complete them
   - Any "advanced" or "beta" features → toggle them
7. ADMIN PANEL (if accessible):
   - Every page, every action, every user management function
8. EXPORT / DOWNLOAD features → these often expose batch endpoints
9. NOTIFICATIONS / MESSAGES → often different API endpoints
10. SEARCH → parametrized endpoint, note all filter fields

DURING CRAWL — watch DevTools for:
- Network tab: every XHR/fetch → copy as curl → save to endpoints.txt
- Application tab → Service Workers registered → note their scope + fetch handlers
- Application tab → localStorage/sessionStorage → look for tokens, user data, flags
- Application tab → Cookies → note all auth-related cookies
- Sources tab → webpack:// entries → readable original source

AFTER CRAWL:
- Export Burp Site Map: right-click target → Save selected items → requests.xml
- Review all unique endpoints in Burp Target → Site Map → filter to scope
```

---

## Phase 4 — JS-Based Surface Recovery

```bash
# Download and beautify all JS files discovered in Phases 1-2
mkdir -p js_files beautified recovered

cat js_urls.txt | sort -u | while read url; do
  filename=$(echo "$url" | md5sum | cut -c1-8).js
  curl -sL "$url" -o "js_files/$filename" 2>/dev/null
done

# Beautify
for f in js_files/*.js; do
  js-beautify "$f" -o "beautified/$(basename $f)" 2>/dev/null
done

# Webcrack: recover webpack module structure
webcrack js_files/*.js -o recovered/ 2>/dev/null

# Extract ALL endpoint patterns from JS
grep -rh 'fetch\|axios\|\.get(\|\.post(\|\.put(\|\.patch(\|\.delete(\|XMLHttpRequest' beautified/ | \
  grep -oE '"(/api/[^"]*|https://[^"]*)"' | sort -u > api_endpoints_from_js.txt

# Extract route definitions (React Router, Next.js, Vue Router)
grep -rh 'path:\|Route path\|router\.get\|router\.post\|app\.get\|app\.post' beautified/ | \
  grep -oE '"(/[^"]*)"' | sort -u > routes_from_js.txt

# Extract all parameters used in API calls
grep -rh 'params:\|?.*=\|body:\|data:' beautified/ | \
  grep -oE '"[a-zA-Z][a-zA-Z_0-9]*"' | sort | uniq -c | sort -rn | head -50 > params_from_js.txt

# Extract SSR state (server renders data into HTML)
for HOST in $(cat live_hosts.txt); do
  curl -sL "https://$HOST" | python3 -c "
import sys, re, json
html = sys.stdin.read()
for key, pat in [('NEXT_DATA', r'__NEXT_DATA__[\"\']\s*>\s*({.+?})</script>'),
                 ('NUXT', r'window\.__NUXT__\s*=\s*(.+?)\s*;'),
                 ('REMIX', r'window\.__remixContext\s*=\s*({.+?})\s*;')]:
    m = re.search(pat, html, re.DOTALL)
    if m:
        print(f'[{key}] Found in https://$HOST/')
        try: print(list(json.loads(m.group(1)).keys()))
        except: print(m.group(1)[:200])
"
done
```

---

## Phase 5 — API Schema Discovery

```bash
# OpenAPI / Swagger spec (drives entire API surface)
for path in /openapi.json /swagger.json /api-docs /v1/api-docs /v2/api-docs /v3/api-docs \
            /swagger.yaml /openapi.yaml /.well-known/openapi.json; do
  url="https://$T$path"
  code=$(curl -s -o /dev/null -w "%{http_code}" "$url")
  if [ "$code" = "200" ]; then
    echo "[SPEC FOUND] $url"
    curl -s "$url" | python3 -c "
import json, sys
spec = json.load(sys.stdin)
print(f'Title: {spec.get(\"info\",{}).get(\"title\",\"?\")}')
print(f'Version: {spec.get(\"info\",{}).get(\"version\",\"?\")}')
endpoints = spec.get('paths',{})
print(f'Endpoint count: {len(endpoints)}')
for path, methods in list(endpoints.items())[:10]:
    for method in methods:
        print(f'  [{method.upper()}] {path}')
" 2>/dev/null
  fi
done

# GraphQL introspection
curl -s "https://$T/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{queryType{fields{name,type{name,kind},args{name,type{name,kind,ofType{name,kind}}}}}}}"}' | \
  python3 -m json.tool 2>/dev/null | head -50

# Full introspection → extract to schema file
curl -s "https://$T/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"'"$(cat ~/.claude/skills/graphql-audit/references/introspection_query.json 2>/dev/null || echo '{__schema{types{name,fields{name,type{name}}}}}')"'"}' | \
  python3 -m json.tool > graphql_schema.json 2>/dev/null

# POSTMAN collections (often publicly searchable)
# Check if the company shared their API on Postman
curl -s "https://www.postman.com/search/collections?q=$T" | grep -oE '"uid":"[^"]*"' | head -5
# Alternative: use truffleHog on public Postman collections
```

---

## Phase 6 — Parameter Discovery

```bash
# Hidden parameters via Arjun (tries wordlist + JS params)
arjun -u "https://$T/api/users" -m GET -oJ arjun_users.json 2>/dev/null
arjun -u "https://$T/api/search" -m GET -oJ arjun_search.json 2>/dev/null

# x8: fast hidden parameter discovery
x8 -u "https://$T/api/" -w ~/.claude/skills/p1-unauth-recon-agent/references/wordlists.md -t 30 2>/dev/null

# Param Miner (Burp): run passively during manual crawl → checks all endpoints for hidden params

# Mine parameters from JS bundles
grep -rh '"[a-zA-Z][a-zA-Z_0-9]*"' beautified/ | \
  grep -oE '"[a-zA-Z][a-zA-Z_0-9]{2,30}"' | \
  tr -d '"' | sort | uniq -c | sort -rn | \
  grep -v 'function\|return\|const\|false\|true\|null\|undefined' | head -100 > js_param_candidates.txt

# Run Arjun with JS-derived wordlist
arjun -u "https://$T/api/search" -m GET -w js_param_candidates.txt 2>/dev/null

# Debug / hidden mode parameters (high signal)
for param in debug test admin internal verbose trace log dev mode enable feature preview beta; do
  for val in 1 true yes enable debug admin; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://$T/api/endpoint?$param=$val")
    [ "$code" = "200" ] && echo "[HIDDEN PARAM] ?$param=$val → 200"
  done
done
```

---

## Phase 7 — Auth Model & Role Mapping

```bash
# Understand the auth model BEFORE testing authorization bugs
# 1. Where does login happen?
# 2. What tokens are issued? (JWT, opaque, session cookie)
# 3. Are roles in the JWT?
# 4. How many user roles exist?
# 5. Is there an admin role? A service account? An API key? An internal user?

# JWT analysis
TOKEN="eyJ..."
python3 -c "
import base64, json
parts = '$TOKEN'.split('.')
for i, part in enumerate(parts[:2]):
    pad = 4 - len(part) % 4
    decoded = base64.urlsafe_b64decode(part + '='*pad)
    print(f'Part {i}: {json.dumps(json.loads(decoded), indent=2)}')
"

# Roles in JWT:
# "role": "user" → test "admin", "superuser", "staff", "internal"
# "scope": "read" → test "write", "admin", "delete"
# "plan": "free" → test "pro", "enterprise"
# "is_admin": false → test true (mass assignment → then check if JWT reflects it)

# Map all endpoints by auth requirement:
# - No token: 200 → unauth endpoint
# - User token: 200 → user endpoint
# - Admin token: 401/403 → auth-required
cat api_endpoints_from_js.txt | while read endpoint; do
  no_auth=$(curl -s -o /dev/null -w "%{http_code}" "https://$T$endpoint")
  with_auth=$(curl -s -o /dev/null -w "%{http_code}" "https://$T$endpoint" -H "Authorization: Bearer $USER_TOKEN")
  echo "$no_auth $with_auth $endpoint"
done | sort > endpoint_auth_map.txt

# Endpoint auth matrix:
grep "^200" endpoint_auth_map.txt | awk '{print "[UNAUTH]", $3}'    # accessible without auth
grep "^401.*200" endpoint_auth_map.txt | awk '{print "[AUTH-OK]", $3}'  # needs token but user token works
grep "^403.*403" endpoint_auth_map.txt | awk '{print "[ADMIN-ONLY?]", $3}'  # blocked for user
```

---

## Phase 8 — WebSocket & SSE Endpoint Mapping

```bash
# WebSocket endpoints from JS
grep -rh 'WebSocket\|new WebSocket\|wss://\|ws://' beautified/ recovered/ | \
  grep -oE '"wss://[^"]*"|"ws://[^"]*"' | sort -u

# SSE endpoints
grep -rh 'EventSource\|new EventSource\|text/event-stream' beautified/ recovered/ | \
  grep -oE '"https?://[^"]*"' | sort -u

# Test WS endpoints without auth
wscat -c "wss://$T/ws" --no-check 2>/dev/null
websocat "wss://$T/ws" --text 2>/dev/null <<< '{"type":"ping"}'

# Test with different Origin headers (CORS on WS)
wscat -c "wss://$T/ws" --header "Origin: https://attacker.com" 2>/dev/null

# Test SSE without auth
curl -s -N "https://$T/api/events" -H "Accept: text/event-stream" | head -20
```

---

## Phase 9 — State Machine Mapping (Multi-Step Flows)

```bash
# Multi-step flows are the richest source of logic bugs
# Map every flow end-to-end and test race conditions, step-skipping, and parameter tampering

# Common flows to map:
# 1. Signup → email verification → onboarding → paid tier
# 2. Password reset → token → new password
# 3. Payment → cart → checkout → payment → confirmation
# 4. File upload → processing → download
# 5. Invite → accept → join org
# 6. Permission request → approval → access
# 7. 2FA setup → verify → enable
# 8. Account deletion → confirmation → grace period

# For each flow, record:
# - Each HTTP request (method, URL, body, headers)
# - What validates each step transition
# - What state is held (token? session var? DB flag?)
# - Can you jump directly to step N without completing 1..N-1?

# Step-skip test: hit step 3's endpoint directly without completing steps 1-2
curl -s "https://$T/api/payment/confirm" -X POST \
  -H "Authorization: Bearer $USER_TOKEN" \
  -d '{"amount":0,"plan":"enterprise"}'
# If it creates an enterprise subscription without payment → P1 business logic

# Parameter tampering on multi-step: change price/quantity/plan at each step
# Step 1: POST /cart {"item_id":1,"qty":1,"price":99.99}
# Step 2: POST /checkout — does the server re-validate price from step 1?
```

---

## Phase 10 — Surface Inventory & Coverage Ledger

After completing all phases, produce a structured inventory:

```bash
# Generate final surface map
cat > surface_map.md <<EOF
# Surface Map: $T — $(date +%Y-%m-%d)

## Auth Model
- Auth mechanism: [JWT/Cookie/API Key]
- Token location: [Header/Cookie/localStorage]
- Roles identified: [list roles from JWT analysis]
- 2FA: [Yes/No/Optional]

## Endpoint Count
- Total unique URLs: $(wc -l < all_urls.txt)
- Parameterized endpoints: $(wc -l < params_urls.txt)
- API endpoints: $(wc -l < api_endpoints_from_js.txt)
- Unauth-accessible: $(grep "^200" endpoint_auth_map.txt | wc -l)
- Admin-only: $(grep "^403.*403" endpoint_auth_map.txt | wc -l)

## Tech Stack
$(curl -s "https://$T" -I | grep -i 'server\|x-powered-by\|x-generator')

## High-Value Targets (ranked by attack potential)
1. [ENDPOINT] — [REASON]
2. [ENDPOINT] — [REASON]
...

## Flows Mapped
- [ ] Signup / registration
- [ ] Login / 2FA
- [ ] Password reset
- [ ] Payment / subscription
- [ ] File upload / download
- [ ] Admin panel
- [ ] API CRUD for main resource

## Coverage Checklist
- [ ] JS recon gate (all chunks, service workers, inline, SSR state)
- [ ] Passive URL collection (wayback + gau + waymore)
- [ ] Active crawl (katana + gospider + hakrawler + cariddi)
- [ ] Directory brute force (feroxbuster)
- [ ] Manual browser crawl (Burp proxy, all routes clicked)
- [ ] API schema (Swagger/GraphQL introspection)
- [ ] Hidden parameter discovery (Arjun + x8)
- [ ] WebSocket + SSE endpoints mapped
- [ ] Auth model documented
- [ ] Role hierarchy mapped
- [ ] Multi-step flows documented
EOF

cat surface_map.md
```

---

## Quick-Reference: Common Missed Surfaces

| Surface | Why Missed | How to Find |
|---|---|---|
| Lazy JS chunks | Crawlers don't trigger lazy routes | Playwright — navigate all SPA routes |
| Service workers | Tools don't check SW paths | Manual: `sw.js`, `service-worker.js`, manifest |
| SSE endpoints | Crawlers don't follow EventSource | Grep JS for `EventSource`, test with curl -N |
| WebSocket endpoints | Tools ignore WS upgrades | Grep JS for `WebSocket`, test with wscat |
| Admin endpoints | Behind auth → crawlers skip | Feroxbuster + wordlist + admin token |
| API v1 (old) | App uses v2 now | Try /v0/ /v1/ /v2/ /beta/ /legacy/ per endpoint |
| Mobile API endpoints | Different base URL in mobile app | Check for /mobile/ /app/ /native/ /ios/ /android/ |
| GraphQL subscriptions | Introspection misses WS transport | Check schema for `Subscription` type |
| Debug endpoints | Only on staging, sometimes leaks to prod | `/debug`, `/trace`, `/test`, `/dev` |
| Internal microservice | Leaked via SSRF / X-headers | Harvest internal URLs from JS/errors |
| Webhook endpoints | App receives webhooks | Grep for webhook/callback in JS, Swagger |
| Batch endpoints | Single-item API has bulk variant | Try `/api/users/batch`, `/api/bulk`, `/api/export` |
