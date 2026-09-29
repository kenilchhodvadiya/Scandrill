# 06 — Dependency CVEs

## Goal
Identify vulnerable JavaScript libraries — both bundled (detected from JS files) and declared (package.json/yarn.lock).

---

## Phase 1: Library Fingerprinting from JS Bundles

```python
# scripts/fingerprint_libs.py
"""
Detects common JS libraries and their versions from bundled JS files.
"""
import re, sys
from pathlib import Path

TARGET = sys.argv[1] if len(sys.argv) > 1 else "js_files"

# Version signature patterns
LIB_PATTERNS = {
    "jQuery":          (r'jquery[:/\s]v?(\d+\.\d+\.\d+)|jQuery v(\d+\.\d+\.\d+)', 'https://security.snyk.io/package/npm/jquery'),
    "lodash":          (r'lodash[/@\s]v?(\d+\.\d+\.\d+)|Lodash <(\d+\.\d+\.\d+)', 'https://security.snyk.io/package/npm/lodash'),
    "axios":           (r'axios[/@\s]v?(\d+\.\d+\.\d+)', 'https://security.snyk.io/package/npm/axios'),
    "angular":         (r'angular[/@\s]v?(\d+\.\d+\.\d+)|AngularJS v(\d+\.\d+\.\d+)', 'https://security.snyk.io/package/npm/angular'),
    "react":           (r'"react":\s*"[^"]*(\d+\.\d+\.\d+)|React v(\d+\.\d+\.\d+)', 'https://security.snyk.io/package/npm/react'),
    "vue":             (r'Vue\.js v(\d+\.\d+\.\d+)|"vue":\s*"[^"]*(\d+\.\d+\.\d+)', 'https://security.snyk.io/package/npm/vue'),
    "bootstrap":       (r'Bootstrap v(\d+\.\d+\.\d+)|bootstrap[/@](\d+\.\d+\.\d+)', 'https://security.snyk.io/package/npm/bootstrap'),
    "moment":          (r'moment\.js|moment[/@](\d+\.\d+\.\d+)', 'https://security.snyk.io/package/npm/moment'),
    "underscore":      (r'Underscore\.js (\d+\.\d+\.\d+)', 'https://security.snyk.io/package/npm/underscore'),
    "handlebars":      (r'handlebars[/@]v?(\d+\.\d+\.\d+)', 'https://security.snyk.io/package/npm/handlebars'),
    "marked":          (r'marked[/@]v?(\d+\.\d+\.\d+)', 'https://security.snyk.io/package/npm/marked'),
    "dompurify":       (r'DOMPurify[/@\s]v?(\d+\.\d+\.\d+)', 'https://security.snyk.io/package/npm/dompurify'),
    "protobufjs":      (r'protobufjs[/@](\d+\.\d+\.\d+)', 'https://security.snyk.io/package/npm/protobufjs'),
    "serialize-js":    (r'serialize-javascript[/@](\d+\.\d+\.\d+)', 'https://security.snyk.io/package/npm/serialize-javascript'),
}

detected = {}

for js_file in Path(TARGET).rglob("*.js"):
    content = js_file.read_text(errors='ignore')
    for lib, (pattern, snyk_url) in LIB_PATTERNS.items():
        m = re.search(pattern, content, re.IGNORECASE)
        if m:
            version = next((g for g in m.groups() if g), "detected (version unknown)")
            if lib not in detected:
                detected[lib] = {"version": version, "file": str(js_file), "snyk": snyk_url}

print(f"\n[FINGERPRINT] Detected {len(detected)} libraries:\n")
for lib, info in detected.items():
    print(f"  [{lib}] version={info['version']}")
    print(f"    File: {info['file']}")
    print(f"    Check CVEs: {info['snyk']}")
    print()
```

---

## Phase 2: npm/yarn Audit (if package.json available)

```bash
# If package.json present
if [ -f package.json ]; then
    echo "[+] Running npm audit..."
    npm audit --json > npm_audit.json 2>/dev/null
    python3 -c "
import json
with open('npm_audit.json') as f:
    data = json.load(f)
vulns = data.get('vulnerabilities', {})
print(f'[NPM AUDIT] {len(vulns)} vulnerable package(s)')
for pkg, info in list(vulns.items())[:20]:
    sev = info.get('severity','?')
    via = [v.get('title','?') if isinstance(v, dict) else str(v) for v in info.get('via',[])[:2]]
    print(f'  [{sev.upper()}] {pkg} — {via}')
"
fi

# yarn audit
if [ -f yarn.lock ]; then
    yarn audit --json > yarn_audit.json 2>/dev/null
fi
```

---

## Phase 3: OSV.dev Lookup for Detected Libraries

```python
# scripts/osv_lookup.py
"""
Queries the OSV.dev API for CVEs affecting detected libraries.
"""
import requests, json, sys

packages = [
    ("jquery", "3.4.1", "npm"),
    ("lodash", "4.17.15", "npm"),
    # Add more from fingerprint_libs.py output
]

# Or read from fingerprint output
if len(sys.argv) > 1:
    with open(sys.argv[1]) as f:
        # Expect JSON: [{"name": "jquery", "version": "3.4.1"}]
        packages = [(p["name"], p["version"], "npm") for p in json.load(f)]

all_vulns = []

for pkg_name, version, ecosystem in packages:
    payload = {
        "package": {"name": pkg_name, "ecosystem": ecosystem},
        "version": version
    }
    try:
        r = requests.post("https://api.osv.dev/v1/query", json=payload, timeout=10)
        data = r.json()
        vulns = data.get("vulns", [])
        if vulns:
            print(f"\n[{pkg_name} {version}] — {len(vulns)} CVE(s):")
            for v in vulns:
                vid = v.get("id", "?")
                summary = v.get("summary", "No summary")[:100]
                severity = v.get("database_specific", {}).get("severity", "?")
                print(f"  [{severity}] {vid}: {summary}")
                all_vulns.append({"package": pkg_name, "version": version, "id": vid, "summary": summary})
        else:
            print(f"[{pkg_name} {version}] No known CVEs")
    except Exception as e:
        print(f"[ERR] {pkg_name}: {e}")

if all_vulns:
    with open("cve_findings.json", "w") as f:
        json.dump(all_vulns, f, indent=2)
    print(f"\n[+] {len(all_vulns)} total CVE(s) saved to cve_findings.json")
```

---

## Phase 4: Retire.js Scan

```bash
retire --path js_files/ --outputformat json --outputpath retire_results.json 2>/dev/null

python3 -c "
import json
with open('retire_results.json') as f:
    data = json.load(f)
critical = []
for item in data:
    for r in item.get('results', []):
        for v in r.get('vulnerabilities', []):
            sev = v.get('severity', '?')
            cve = v.get('identifiers', {}).get('CVE', ['N/A'])
            print(f'[{sev.upper()}] {r[\"component\"]} {r[\"version\"]} — CVE: {cve}')
            if sev in ['high', 'critical']:
                critical.append(r)
print(f'\n[SUMMARY] {len(critical)} critical/high severity findings')
"
```

---

## High-Value CVEs to Look For in JS (updated through 2025)

### Classic / Evergreen

| Library | Version Range | CVE | Impact |
|---------|--------------|-----|--------|
| jQuery | < 3.5.0 | CVE-2020-11022/23 | XSS via html() |
| lodash | < 4.17.21 | CVE-2021-23337 | Command injection |
| lodash | < 4.17.19 | CVE-2020-8203 | Prototype pollution |
| handlebars | < 4.7.7 | CVE-2021-23369 | Template injection RCE |
| marked | < 4.0.10 | Multiple | XSS |
| serialize-javascript | < 3.1.0 | CVE-2020-7660 | XSS |
| DOMPurify | < 2.0.17 | Multiple | XSS bypass |
| axios | < 0.21.1 | CVE-2020-28168 | SSRF |
| protobufjs | < 6.11.3 | CVE-2022-25878 | Prototype pollution |
| vm2 | < 3.9.11 | CVE-2022-36067 | Sandbox escape |

### 2023-2025 Critical (HIGH PRIORITY — mass-exploited)

| Library | Version Range | CVE | Impact | Notes |
|---------|--------------|-----|--------|-------|
| **Next.js** | ≤ 15.2.2 | **CVE-2025-29927** | **Middleware auth bypass** | Spoof `x-middleware-subrequest` header → skip all middleware |
| Next.js | ≤ 14.2.24 / ≤ 15.2.2 | CVE-2025-32421 | Cache poisoning via malformed headers | DoS + cache poisoning |
| Next.js | ≤ 13.5.6 | CVE-2024-46982 | Cache poisoning | Unkeyed header in static file serving |
| **Vite** | < 5.0.12 / < 4.5.5 | **CVE-2024-23331** | **Path traversal on dev server** | `/@fs/etc/passwd` when `allowedHosts` not set |
| Vite | < 6.2.3 / < 5.4.15 | CVE-2025-32395 | Server-side request via `@fs` bypass | |
| **webpack** | < 5.76.0 | CVE-2023-28154 | Prototype pollution via loaders | |
| express | < 4.19.2 | CVE-2024-29041 | Open redirect | `res.redirect` with user-controlled URL |
| express | < 4.21.1 | CVE-2024-43796 | XSS via `res.redirect` on encoded URLs | |
| **jose** | < 4.15.5 | CVE-2024-28176 | Algorithm confusion → auth bypass | RS256 key confusion |
| **jsonwebtoken** | < 9.0.0 | CVE-2022-23529 | Secret injection → auth bypass | |
| node-fetch | < 3.3.2 | CVE-2022-0235 | SSRF via redirect | |
| **Babelfish/marked** | < 5.0.0 | CVE-2023-37300 | ReDoS | Regex DoS in markdown parser |
| semver | < 5.7.2 / < 6.3.1 / < 7.5.2 | CVE-2022-25883 | ReDoS | Extreme slow regex on crafted version string |
| tough-cookie | < 4.1.3 | CVE-2023-26136 | Prototype pollution | Cookie parsing |
| **ws** | < 8.17.1 | CVE-2024-37890 | DoS via headers | HTTP/1.1 upgrade header — crashes WS server |
| tar | < 6.2.1 | CVE-2024-28863 | ReDoS | |
| pdfjs-dist | < 4.2.67 | CVE-2024-4367 | XSS via JS execution in PDF | |
| **dompurify** | < 3.1.3 | CVE-2024-47875 | XSS bypass via mXSS mutation | |
| katex | < 0.16.10 | CVE-2024-28243-8 | XSS via LaTeX rendering | |
| sanitize-html | < 2.12.1 | CVE-2024-21501 | XSS bypass | |
| **Rollup** | < 3.29.5 / < 4.22.4 | CVE-2024-47068 | Code injection in generated bundles | DOM clobbering in generated output |
| esbuild | ≤ 0.24.2 | CVE-2025-25193 | Arbitrary file read on dev server | `/@fs/` path escape |

---

## Reporting a Dependency CVE

**Severity uplift conditions:**
- Library serves as security boundary (DOMPurify, CSP bypass) → Critical
- Version is end-of-life → add "no patch available" note
- Proof that the vulnerable code path is reachable from user input → High
- Library only used in build tooling, not shipped to users → Informational
