# 01 — JS Discovery

## Goal
Extract every JS file reachable from a target: bundles, chunks, workers, source maps, dynamically loaded scripts.

---

## Phase 0: Enumerate every subdomain FIRST — this pipeline runs once PER live host, not once for the apex domain

**HARD RULE:** `target.com` is not "the target" — every live subdomain is a separate
target for this pipeline. A subdomain can run a completely different frontend with its
own bundle, its own leaked secrets, its own logic bugs. Do not assume a subdomain
"probably shares the same build" as the apex domain — verify (diff bundle hashes/sizes)
rather than assume, and if it's a different build, it gets its own full Phase 1-6 pass.

```bash
# Enumerate every subdomain before touching JS at all
subfinder -d target.com -all -silent -o subs.txt
assetfinder --subs-only target.com >> subs.txt
sort -u subs.txt -o subs.txt

# Confirm which are actually live and get tech/title context
httpx -l subs.txt -silent -status-code -title -tech-detect -o live_hosts.txt
```

Then repeat **every phase below** (1 through 6) against each live host in
`live_hosts.txt` independently — not just the one that looks like the main app. Bot
webhook servers, QA/staging copies, internal tools, admin panels: all of them. If a host
serves zero JS, note it and move to the next — but every host must be checked, not
assumed.

---

## Phase 1: Passive Discovery (No Active Requests to Target)

```bash
# Pull historical JS URLs from archives
echo "https://target.com" | waybackurls | grep "\.js" | sort -u > js_wayback.txt
echo "https://target.com" | gau --subs | grep "\.js" | sort -u > js_gau.txt

# waymore — combines WaybackMachine + CommonCrawl + AlienVault + URLScan (more coverage)
waymore -i target.com -mode U -oU waymore_urls.txt 2>/dev/null
grep '\.js' waymore_urls.txt >> js_wayback.txt

# Merge and deduplicate
cat js_wayback.txt js_gau.txt | sort -u > js_all_passive.txt
```

---

## Phase 2: Active Crawl

```bash
# katana crawl — extracts JS from HTML + dynamic rendering + form fields + headers
katana -u https://target.com -jc -jsl -d 5 -kf all -aff -silent | grep "\.js" | sort -u > js_katana.txt

# gospider for additional coverage
gospider -s https://target.com -d 3 --js | grep "\.js" | sort -u >> js_katana.txt

# cariddi — fast, recursive crawler with JS endpoint extraction
cariddi -s https://target.com -intensive 2>/dev/null | grep '\.js' >> js_katana.txt

# hakrawler — additional endpoint extraction
hakrawler -u https://target.com -d 3 -subs 2>/dev/null | grep '\.js' >> js_katana.txt

# Merge all sources
cat js_all_passive.txt js_katana.txt | sort -u > js_master_list.txt
```

---

## Phase 2b: Service Worker Discovery (MANDATORY — usually skipped, high yield)

Service workers intercept ALL network requests and often contain hardcoded endpoints, cache
strategies exposing internal APIs, and even credentials for push notifications.

```bash
# Common service worker paths
for path in sw.js service-worker.js serviceworker.js sw-prod.js worker.js firebase-messaging-sw.js push-worker.js; do
  status=$(curl -sL -o /dev/null -w "%{http_code}" "https://target.com/$path")
  [ "$status" = "200" ] && echo "[SW FOUND] https://target.com/$path" && \
    curl -sL "https://target.com/$path" >> js_master_list.txt
done

# Parse Web App Manifest for SW registration
curl -sL https://target.com/manifest.json | jq -r '
  .start_url, .scope,
  (.shortcuts[]?.url // empty),
  (.icons[]?.src // empty)' 2>/dev/null

# Find SW registration in HTML/JS (the JS itself registers the SW)
grep -rE "navigator\.serviceWorker\.register\s*\(['\"]([^'\"]+)['\"]" beautified/ | \
  grep -oE "['\"][^'\"]+['\"]" | tr -d "'\""
```

---

## Phase 2c: Inline JS Extraction from HTML (MANDATORY)

Inline `<script>` blocks are invisible to URL-based crawlers. They frequently contain
hardcoded API keys, config objects, user session data, and internal API base URLs.

```python
# scripts/extract_inline_js.py
import re, sys, os, requests
from bs4 import BeautifulSoup

HOST = sys.argv[1]  # e.g. "target.com"
PATHS = ['/', '/app', '/dashboard', '/admin', '/login', '/register',
         '/settings', '/account', '/profile', '/home', '/index.html']
os.makedirs('js_files', exist_ok=True)

for path in PATHS:
    try:
        r = requests.get(f"https://{HOST}{path}", timeout=12,
                         headers={"User-Agent": "Mozilla/5.0 (compatible; Googlebot)"})
        soup = BeautifulSoup(r.text, 'html.parser')

        # Extract <script> blocks
        for i, tag in enumerate(soup.find_all('script', src=False)):
            content = tag.string or ''
            if len(content.strip()) > 50:
                fname = f"js_files/inline_{path.strip('/') or 'root'}_{i}.js"
                with open(fname, 'w') as f:
                    f.write(content)
                print(f"[INLINE] Extracted {len(content)} chars → {fname}")

        # Hunt SSR state blobs (Next.js, Nuxt, Remix, SvelteKit) — HIGH VALUE
        ssr_patterns = {
            '__NEXT_DATA__':    r'<script[^>]*id=["\']__NEXT_DATA__["\'][^>]*>({.+?})</script>',
            '__NUXT__':         r'window\.__NUXT__\s*=\s*(.+?)\s*(?:;|\n)',
            '__remixContext':   r'window\.__remixContext\s*=\s*({.+?})\s*;',
            '__SVELTE__':       r'window\.__SVELTE__\s*=\s*({.+?})\s*;',
            'initialState':     r'window\.initialState\s*=\s*({.+?})\s*;',
            'bootstrapData':    r'window\.bootstrapData\s*=\s*(["\']?.+?["\']?)\s*;',
        }
        for name, pat in ssr_patterns.items():
            m = re.search(pat, r.text, re.DOTALL)
            if m:
                fname = f"js_files/ssr_{name}_{path.strip('/') or 'root'}.json"
                with open(fname, 'w') as f:
                    f.write(m.group(1))
                print(f"[SSR-STATE] {name} FOUND at {HOST}{path} → {fname}")
                print(f"  CHECK FOR: tokens, user data, internal API URLs, env vars")

    except Exception as e:
        print(f"[ERR] {path}: {e}")

print("[DONE] Inline JS extraction complete")
```

```bash
python scripts/extract_inline_js.py target.com
```

---

## Phase 2d: Framework-Specific Chunk Enumeration

### Next.js
```bash
# Next.js exposes a build manifest listing ALL chunk paths
curl -s "https://target.com/_next/static/chunks/pages/_app.js" | head -2  # confirm Next.js
curl -s "https://target.com/_next/static/build-manifest.json" | \
  python3 -c "import json,sys; d=json.load(sys.stdin); [print(v) for vv in d.get('pages',{}).values() for v in (vv if isinstance(vv,list) else [])]" | \
  sed 's|^|https://target.com/_next/|' | anew js_master_list.txt

# Also check react-loadable-manifest, client-reference-manifest (App Router)
for manifest in build-manifest.json react-loadable-manifest.json client-reference-manifest.json; do
  curl -s "https://target.com/_next/static/$manifest" | jq -r '.. | strings | select(test("^static/"))' | \
    sed 's|^|https://target.com/_next/|' | anew js_master_list.txt 2>/dev/null
done
```

### Nuxt
```bash
# Nuxt exposes payload JSON + chunk manifest
curl -s "https://target.com/_nuxt/manifest.json" | jq -r '.[].file // .[].js // .[].css' | \
  grep '\.js$' | sed 's|^|https://target.com/_nuxt/|' | anew js_master_list.txt 2>/dev/null
```

### Vite / Generic SPA
```bash
# Vite assets directory
curl -s "https://target.com/assets/" | grep -oE '[a-zA-Z0-9\-\.]+\.[a-f0-9]{8}\.js' | \
  sed 's|^|https://target.com/assets/|' | anew js_master_list.txt 2>/dev/null
```

---

## Phase 3: Source Map Detection

Source maps are gold — they expose original unminified source.

```bash
# Check each JS URL for companion .map file
while read url; do
  map_url="${url}.map"
  status=$(curl -s -o /dev/null -w "%{http_code}" "$map_url")
  if [ "$status" = "200" ]; then
    echo "[SOURCE MAP FOUND] $map_url"
    curl -s "$map_url" -o "$(basename $map_url)"
  fi
done < js_master_list.txt
```

**Source map recovery with sourcemapper:**
```bash
pip install sourcemapper --break-system-packages
sourcemapper -url https://target.com/static/main.abc123.js.map -output ./recovered_source/
```

---

## Phase 4: Download All JS Files

```bash
# Bulk download with metadata
mkdir -p js_files
while read url; do
  filename=$(echo "$url" | md5sum | cut -d' ' -f1).js
  curl -s -A "Mozilla/5.0" "$url" -o "js_files/$filename"
  echo "$filename $url" >> js_url_map.txt
done < js_master_list.txt

echo "[+] Downloaded $(ls js_files/ | wc -l) JS files"
```

---

## Phase 5: Webpack / SPA Bundle Analysis

```bash
# Install webpack-exploder / js-beautify
npm install -g js-beautify
pip install jsbeautifier --break-system-packages

# Beautify minified files for readable analysis
for f in js_files/*.js; do
  js-beautify "$f" > "beautified/$(basename $f)"
done

# Find webpack chunk loading (reveals all chunk URLs)
grep -r "webpackChunk\|__webpack_require__\|chunkId" js_files/ | head -50

# Extract all dynamic import() paths
grep -rE "import\(['\"]([^'\"]+)['\"]\)" js_files/ | grep -oE "['\"][^'\"]+['\"]"
```

---

## Phase 6: HAR File Analysis

When user provides a HAR file or Burp export:

```python
# scripts/har_js_extractor.py
import json, sys, os, re

har_file = sys.argv[1]
output_dir = "har_js_extracted"
os.makedirs(output_dir, exist_ok=True)

with open(har_file) as f:
    har = json.load(f)

js_entries = []
for entry in har['log']['entries']:
    url = entry['request']['url']
    mime = entry['response']['content'].get('mimeType', '')
    if 'javascript' in mime or url.endswith('.js'):
        content = entry['response']['content'].get('text', '')
        if content:
            fname = re.sub(r'[^\w]', '_', url)[-60:] + '.js'
            with open(f"{output_dir}/{fname}", 'w') as out:
                out.write(content)
            js_entries.append(url)
            print(f"[+] Extracted: {url}")

print(f"\n[DONE] {len(js_entries)} JS files extracted to {output_dir}/")
```

```bash
python scripts/har_js_extractor.py capture.har
```

---

## Checklist

- [ ] Every subdomain enumerated and probed live (Phase 0) — not just the apex domain
- [ ] Wayback + gau + **waymore** passive discovery, run per live host
- [ ] katana + gospider + **cariddi** + hakrawler active crawl, run per live host
- [ ] **Service workers discovered and downloaded** (`sw.js`, `service-worker.js`, manifest-registered paths)
- [ ] **Inline JS extracted** from HTML pages including SSR state blobs (`__NEXT_DATA__`, `__NUXT__`, `__remixContext`)
- [ ] **Framework chunk manifests fetched** (Next.js `build-manifest.json`, Nuxt `manifest.json`, Vite `/assets/`)
- [ ] Source map detection + recovery, run per live host
- [ ] Webpack chunk enumeration (including pulling the chunk-id→hash map out of the
      runtime bootstrap to catch lazy-loaded chunks a crawler didn't happen to trigger)
- [ ] All files downloaded and beautified
- [ ] **Obfuscated files deobfuscated** with webcrack / synchrony before reading
- [ ] **Every single beautified/deobfuscated file READ IN FULL, end to end — not
      grepped.** This has no file-count exception: if there are hundreds of files across
      dozens of subdomains, all of them still get read. Grep finds keyword hits; it does
      not surface the logic bug in a feature that never mentions "auth" or "admin" in a
      variable name. Budget the time for this — it is supposed to be slow.
- [ ] HAR/Burp export extracted (if provided)
- [ ] **WebSocket/SSE endpoints noted** during manual crawl (Network tab, WS filter)
