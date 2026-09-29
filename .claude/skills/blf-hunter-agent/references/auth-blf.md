# Auth & Session BLF — Logic Flaws in Authentication Flows

## 2FA / MFA Bypass Patterns

```
METHOD 1: Step Skip
- Complete username + password (step 1)
- Do NOT submit 2FA code
- Directly browse to authenticated endpoint: /dashboard, /api/user
- If session is created at step 1 (before 2FA) → bypass
- Test: check Set-Cookie after step 1

METHOD 2: OTP Not Invalidated
- Request OTP → use it → request another OTP → old one still works
- Race: submit same OTP 20x simultaneously → may all pass
- No brute-force protection: enumerate 6-digit code (0-999999)

METHOD 3: Response Manipulation
- POST /auth/verify-2fa {"code": "000000"}
- Response: {"success": false, "next": "/2fa"}
- Modify response: {"success": true, "next": "/dashboard"}
- Check if server honors modified state on next request

METHOD 4: Backup Code Abuse  
- Generate backup codes → use all → regenerate
- Race code regeneration + last code use
- Backup codes without rate limit

METHOD 5: 2FA on Account Recovery Only
- Forgot password flow bypasses 2FA entirely
- Reset password → log in → no 2FA prompt

METHOD 6: Trust on First Device Flag
- "Remember this device" flag in cookie or JWT
- Modify flag: remember_device=false → true
- Or steal remember_device token for victim
```

## Password Reset Logic Flaws

```
METHOD 1: Token Not Invalidated After Use
- Request reset → use link → request another → OLD link still works
- Test: reset → log in → request new reset → use first link again

METHOD 2: Token Tied to Email, Not Account
- Request reset for victim → token sent to victim
- But token validation only checks token validity, not who requested
- Combine with email change IDOR

METHOD 3: Predictable Token
- Token = base64(email + timestamp) → predict
- Token = MD5(email) → enumerate
- Sequential numeric IDs → enumerate

METHOD 4: Host Header Injection
- POST /forgot-password with Host: attacker.com
- Reset email contains: https://attacker.com/reset?token=ABC
- Token sent to attacker's server

METHOD 5: Cross-User Token
- Request reset for user A → get token
- Use token for user B → server only validates token format, not binding

METHOD 6: Token in URL (Logged)
- Reset link: /reset?token=SECRET
- Token appears in server logs, referer headers, browser history
- If logs accessible (via LFI/SSRF) → harvest tokens
```

## Session Management BLF

```
METHOD 1: Session Not Rotated on Privilege Change
- Log in as user → get session token
- Admin upgrades your account
- Old session token now has admin privileges without re-auth

METHOD 2: Concurrent Session Abuse
- Log in on device A → session A
- Log in on device B → session B
- Both sessions remain valid
- If app grants trial to "new sessions" → create infinite sessions

METHOD 3: Session After Logout (Cache)
- Log out → session cookie cleared from browser
- BUT if you saved the cookie → it still works server-side
- Test: copy cookie before logout → use after

METHOD 4: Session Fixation
- Attacker sets session: /login?session_id=ATTACKER_CHOSEN
- Victim logs in → server accepts that session ID
- Attacker now authenticated as victim

METHOD 5: JWT Algorithm Confusion
- alg: RS256 → try alg: HS256 with public key as secret
- alg: none → remove signature entirely
- JWT kid header: path traversal, SQLi

METHOD 6: JWT Claims Not Validated
- exp claim: set far future → never expires
- iss claim: change to other service's issuer
- role claim: user → admin
- sub claim: your_id → victim_id
```

## OAuth & SSO Logic Flaws

```
OAUTH:
□ Missing state parameter → CSRF login
□ redirect_uri: evil.com, evil.com/callback, legitimate.com.evil.com
□ scope escalation: request read → get read+write
□ Auth code reuse: code not invalidated after first exchange
□ Token leakage: access_token in URL → appears in logs/referer
□ Account linking CSRF: link attacker OAuth to victim account
□ Open redirect in OAuth flow: redirect_uri= → steal code

SAML:
□ Signature wrapping: copy valid signed element, inject unsigned admin element
□ Comment injection: user<!---->admin → parsed as "useradmin" by some parsers
□ XML external entity: SAML response with XXE payload
□ Role/email attribute manipulation: change role="admin" in assertion
□ Replay: SAML assertions without NotBefore/NotAfter → replay old assertion

SSO LOGIC:
□ SP-initiated vs IdP-initiated: skip SP auth check via IdP-initiated flow
□ Tenant isolation: authenticate to Tenant A → access Tenant B
□ JIT provisioning: malformed SSO response creates admin account
□ Logout not propagated: log out of SP but IdP session remains
```

## Account Registration & Verification Logic

```
□ Email verification skip: register → access app before verifying email
□ Duplicate registration: race account creation with same email
□ Username enumeration: timing difference on /forgot-password
□ Email case sensitivity: User@Email.com ≠ user@email.com in DB → two accounts
□ Unicode normalization: café@test.com → cafe@test.com → same mailbox, different DB records  
□ Subdomain email: user+admin@target.com → creates admin-level account
□ Invitation token: accept invite as different user than intended recipient
□ Account hijacking pre-registration: register with victim's email before they do
□ Verification link: does not expire, works for different account
□ Phone number: reassigned numbers accepted as valid verification
□ Username/identifier reuse → ATO: see below
```

### Username / Identifier Reuse → Account Takeover

Root cause: resource ownership, ACLs, group/org membership, invites, @mentions,
billing, and audit references are keyed on a MUTABLE identifier (username,
handle, email, team/org slug) instead of an immutable user ID. When account A is
deleted or renamed, its handle is freed; any orphaned resource still
string-matched to that handle gets silently re-bound to whoever claims it next.

```
□ Deletion-reclaim:  A deletes account → register new account, set username = A's old handle → inherit A's resources
□ Rename-reclaim:    A renames to "A2" (frees "A") → rename YOUR account to "A" → inherit A's resources
□ Email reuse:       A changes email away → register/rebind with A's old email → inherit A's account links
□ Slug reuse:        org/team deleted or renamed → recreate with same slug → inherit old members/invites/data
□ OAuth re-link:     provider re-uses sub/handle → new owner of handle gets old account's linked identity
```

What to confirm after the reclaim: does the new account see the previous owner's
shared docs, group/org membership, OAuth links, profile data, history, or
billing? If yes = cross-account access / ATO (High–Critical, victim took no
unusual action beyond having existed). Fix is to key everything on an immutable
user ID and hard-revoke orphaned grants on deletion/rename.

## Account Lifecycle / Offboarding Desync (Zombie Account)

Root cause: a lifecycle transition (delete / ban / suspend / deactivate /
downgrade / close-org / offboard) is enforced at ONE chokepoint — almost always
login/auth — but is NOT fan-out-propagated to the other subsystems the account
touches. The account becomes a **zombie**: dead for login, alive for
sessions / API keys / webhooks / invoicing / payouts / credits. Any asymmetry
between subsystems is the bug; financial asymmetry is the highest impact and
usually lives in the **platform / billing layer, not the target app**.

🚩 Canonical tell: *"Account deleted → login says Not Found, but invoice still
generates → payout still missing."* Test the lifecycle of YOUR OWN account on
the platform/billing layer — not just the target's features.

```
ZOMBIE SWEEP — run after ANY lifecycle transition:
1. MAP subsystems: login, live sessions, API keys/PATs, OAuth grants + refresh
   tokens, webhooks, scheduled/cron jobs, billing/invoicing, payouts,
   referral/credit ledger, team/org membership, shared docs, exports, signed URLs.
2. CAPTURE artifacts BEFORE transition: session cookie, API key, OAuth/refresh
   token, signed URL, deep link.
3. TRIGGER transition: self-delete / get banned / suspend / downgrade / close org.
4. REPLAY each artifact against each subsystem POST-transition.
5. ASYMMETRY = finding (works in X, blocked in Y).

MANIFESTATIONS / SEVERITY:
□ Offboarded API key/PAT still authenticates        → persistent access (P1)
□ Old session cookie survives delete/ban            → ban evasion / post-delete access
□ Banned user's refresh/OAuth token still mints      → ban bypass via token refresh
□ Deleted acct still generates invoices / burns meter → billing fraud (platform eats liability)
□ Deactivated org still receives webhooks w/ PII     → data leak
□ Downgraded acct keeps premium entitlements         → feature theft
□ Generate-liability works but settle-liability blocked → accounting desync / money machine
```

Fix: on every lifecycle transition, hard-revoke ALL sessions, API keys, OAuth
grants and refresh tokens; stop webhooks/cron; gate every subsystem on the
account's current state (not just the auth/login path).

## Privilege Escalation Patterns

```
VERTICAL (user → admin):
□ role parameter in update request
□ is_admin, is_staff boolean flag
□ account_type, plan, tier manipulation
□ Admin API endpoint accessible with user token
□ Function-level access control missing on specific endpoint

HORIZONTAL (user A → user B):
□ user_id, account_id in request body → change to victim
□ Shared resources via predictable IDs
□ Team/org scoping missing on nested resources
□ Cross-tenant API access via organization parameter

LATERAL (feature bypass):
□ Disabled feature → accessible via direct API call
□ Beta/internal feature via X-Beta-User header
□ Premium feature check only in UI, not API
□ Admin-only report accessible to regular user
```
