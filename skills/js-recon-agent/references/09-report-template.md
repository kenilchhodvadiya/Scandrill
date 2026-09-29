# 09 — Report Template

## Severity Mapping for JS Findings

| Finding Type | Base Severity | Upgrade Conditions |
|---|---|---|
| Valid API key (read-only) | Medium | → High if PII accessible |
| Valid API key (write/admin) | Critical | |
| JWT secret hardcoded | Critical | |
| PII in JS (emails, names) | Low–Medium | → High if financial/health PII |
| Internal endpoint exposed | Medium | → High if auth bypass |
| DOM XSS | Medium–High | → Critical if steals session |
| Prototype Pollution | Medium | → High with working XSS gadget chain |
| IDOR (read) | Medium–High | depends on data sensitivity |
| IDOR (write/delete) | High–Critical | |
| BAC (admin access) | Critical | |
| CVE in dep (PoC exists) | High | |
| CVE in dep (no PoC / informational) | Low–Medium | |
| Source map exposed | Informational–Low | → Medium if secrets in source |
| Debug endpoints active | Low–Medium | → High if data exposed |

---

## Full Bug Report Template

```markdown
# [BUG CLASS] — [Brief Title]
**Severity:** [Critical / High / Medium / Low / Informational]
**CVSS Score:** [e.g. 8.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)]
**CWE:** [e.g. CWE-922: Insecure Storage of Sensitive Information]

---

## Summary
[1–3 sentence description of the vulnerability and its impact. Be specific about what data or actions are exposed.]

## Vulnerability Details

**Asset:** `[URL / file / component]`
**Location:** `[specific file, line number, or endpoint]`
**Root Cause:** [Why this is vulnerable — e.g., "API key hardcoded in client-side bundle"]

## Impact
[What an attacker can do if they exploit this:]
- [Impact point 1]
- [Impact point 2]

**Business Impact:** [e.g., "An attacker could exfiltrate all customer records via the admin API"]

## Steps to Reproduce

1. Navigate to `[URL]`
2. Open DevTools → Sources → search for `[pattern]`
3. [Continue steps...]
4. [Final result observed]

## Proof of Concept

```[language]
[Minimal PoC code or curl command]
```

**PoC Output:**
```
[Expected output showing the vulnerability]
```

## Suggested Remediation
- [Fix 1 — e.g., "Move API keys to server-side environment variables"]
- [Fix 2 — e.g., "Implement server-side authorization checks"]
- [Reference: OWASP link or relevant security guide]

## References
- [CVE link if applicable]
- [OWASP reference]
- [Any related writeups]
```

---

## Bug-Class Specific Report Snippets

### Secret / Token Leak

```markdown
## Summary
A [SERVICE_NAME] API key was discovered hardcoded in the client-side JavaScript bundle at
`[FILE_URL]`. The key grants [read/write/admin] access to [service description].

## PoC
curl -H "Authorization: Bearer [REDACTED_KEY]" https://api.service.com/v1/users

## Response (confirms key is valid):
{"users": [...], "total": 1547}
```

### DOM XSS

```markdown
## Summary
The application reflects unsanitized user input from `location.hash` into an `innerHTML` sink,
enabling arbitrary JavaScript execution in the context of [target origin].

## PoC URL
https://target.com/page#search=<img src=x onerror=alert(document.domain)>

## Impact
- Session hijacking via `document.cookie` theft
- Credential phishing via DOM manipulation
- CSRF action chains
```

### IDOR

```markdown
## Summary
The `/api/users/{id}/profile` endpoint returns user profile data for any user ID without
verifying that the requesting user owns that resource. An attacker can enumerate user IDs
to access other users' private information.

## PoC
# Attacker (user_id=111) accesses victim (user_id=222):
curl -H "Authorization: Bearer [ATTACKER_TOKEN]" \
  https://api.target.com/users/222/profile

## Response: victim's full profile including email, phone, address
```

### Prototype Pollution

```markdown
## Summary
The `mergeConfig()` function in `bundle.js` performs an unsafe deep merge of URL query
parameters into an object, allowing pollution of `Object.prototype`. A proof-of-concept
demonstrates escalation to DOM XSS via the `innerHTML` gadget.

## PoC
https://target.com/?__proto__[innerHTML]=<img src=x onerror=alert(1)>
```

---

## CVSS v3.1 Quick Reference for JS Bugs

```
Secret Leak (valid active key, read access):
AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5 (High)

DOM XSS (user-interaction required):
AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N = 8.2 (High)

IDOR (read, sensitive data):
AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5 (Medium)

IDOR (write/delete, any user's data):
AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N = 8.1 (High)

Prototype Pollution → XSS:
AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N = 8.7 (High)

BAC (admin API accessible to low-priv user):
AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H = 9.9 (Critical)
```
