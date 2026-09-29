# BLF Chain Escalation — From Low to Critical

## The Chain Mindset

> A single BLF is a finding. A chained BLF is a payday.
> Always ask: "What else can I do WITH this bug?"

## High-Value Chain Patterns

### Chain 1: IDOR → ATO (Account Takeover)
```
Step 1: IDOR on email change endpoint (low severity alone)
  PATCH /api/user/profile → change victim's email to attacker@evil.com

Step 2: Password reset (legitimate feature)
  POST /auth/forgot-password {"email": "attacker@evil.com"}
  → Reset link sent to attacker

Result: FULL ACCOUNT TAKEOVER
Severity: Critical
```

### Chain 2: Race Condition + Coupon = Infinite Discount
```
Step 1: Identify one-time coupon endpoint
  POST /checkout/apply-coupon {"code": "SAVE100"}

Step 2: Race 20 requests simultaneously (Turbo Intruder)
  → Multiple redemptions succeed before server flags code as used

Step 3: Each redeemed instance grants $100 discount
  → Purchase $100 item 20x for free

Result: FINANCIAL FRAUD AT SCALE
Severity: Critical
```

### Chain 3: Feature Flag + Sensitive Export = Data Exfil
```
Step 1: Flip client-side feature flag
  X-Feature: {"enterprise_export": true} in request header
  → Server trusts header (no server-side validation)

Step 2: Access enterprise export endpoint
  GET /api/export/all-users?format=csv
  → Returns all user PII (unauthorized)

Result: DATA BREACH
Severity: Critical
```

### Chain 4: Step Skip + Financial Feature = Fraud Gateway
```
Step 1: KYC step skip
  POST /api/v1/kyc/complete (forced browse without prior steps)
  → Account marked as KYC-verified without verification

Step 2: Access financial features gated behind KYC
  POST /api/v1/withdraw {"amount": 10000, "account": "attacker"}
  → Withdrawal processed without identity verification

Result: FINANCIAL FRAUD ENABLEMENT
Severity: Critical
```

### Chain 5: Negative Quantity + Gift Card = Money Generation
```
Step 1: Add item with negative quantity
  POST /cart {"item_id": "gift_card_100", "quantity": -1}
  → Cart total goes NEGATIVE (server adds negative price)

Step 2: Apply to account credit
  → Account credited $100 without payment

Step 3: Repeat or race
  → Infinite money

Result: DIRECT FINANCIAL LOSS TO COMPANY
Severity: Critical
```

### Chain 6: Response Manipulation + Role Escalation
```
Step 1: Login → intercept response
  Response: {"role": "user", "is_admin": false}
  Modified: {"role": "admin", "is_admin": true}

Step 2: Check if server now honors admin role
  GET /api/admin/users → returns user list?

Step 3: If yes → access admin endpoints
  POST /api/admin/make-refund → arbitrary refund
  GET /api/admin/export → all user data

Result: PRIVILEGE ESCALATION → DATA BREACH / FINANCIAL FRAUD
Severity: Critical

NOTE: Response manipulation alone = usually invalid (client-side)
      The key is if subsequent SERVER requests honor the manipulated state
```

### Chain 7: Referral Loop → Infinite Credits
```
Step 1: Account A refers Account B
  → Both get $10 credit

Step 2: Account B refers Account A (or Account A refers self)
  → Server doesn't check circular referral
  → Both get another $10

Step 3: Automate with script
  → $X infinite credits

Result: FINANCIAL FRAUD
Severity: High/Critical (depends on credit to cash conversion)
```

### Chain 8: Expired Token + Race = Extended Session
```
Step 1: Let trial expire
Step 2: At expiry boundary (T+0), send parallel requests:
  - Request A: trial expiry check
  - Request B: access premium feature
  → Race window allows B to succeed after expiry

Result: UNAUTHORIZED PREMIUM ACCESS
Severity: Medium (may chain to higher depending on features)
```

### Chain 9: Invite Logic → Bypass Seat Cap
```
Step 1: Organization at seat limit (5/5 seats)
Step 2: Race invite requests
  - Send 10 simultaneous POST /invites for 10 new users
  - Server checks "seats_used < max_seats" for each → all pass check
  → 10 users join, organization has 15/5 seats

Result: SaaS REVENUE FRAUD
Severity: High
```

### Chain 10: Android IAP + API Race = Unlimited Subscription
```
Step 1: Buy 1-month subscription (legitimate)
  → Get purchase_token from Google Play

Step 2: Race token verification endpoint
  POST /api/verify-purchase {"token": "valid_token"}
  × 20 simultaneous

Step 3: Each verification might grant +1 month
  → 20 months for price of 1

Result: SUBSCRIPTION FRAUD
Severity: High
```

## Chain Discovery Framework

When you find a low/medium BLF, ask:
```
1. WHO benefits from this bug? (attacker role)
2. WHAT state does this bug change? (DB field, session, balance)
3. WHAT can I do WITH that changed state? (follow-up actions)
4. IS there a financial/data/access component downstream?

If YES to #4 → chain it and re-rate severity
```

## Severity Escalation Matrix

| Base Finding | Chain With | Result Severity |
|-------------|-----------|----------------|
| IDOR (read own data) | Affects financial state | High |
| IDOR (other user data) | Email change → reset | Critical (ATO) |
| Client-side flag flip | Backend export endpoint | Critical |
| Step skip | Reaches payment/data | Critical |
| Race condition | Financial transaction | Critical |
| Negative quantity | Credit/refund system | Critical |
| Role parameter | Admin functionality | Critical |
| Coupon reuse | Race for scale | High/Critical |
| Referral self-loop | Auto-exploitation | High |
| Session not invalidated | Concurrent session access | Medium |

## Report Writing for Chains

```
Title: [Chain]: [BLF1] + [BLF2] → [Critical Impact]

Example: 
"Race Condition in Coupon Redemption + Missing Server-Side Use Tracking 
→ Unlimited $100 Discounts (Financial Fraud)"

In Steps to Reproduce:
1. [Set up initial condition]
2. [Trigger BLF1]
3. [Use BLF1's effect to amplify BLF2]
4. [Show critical outcome]
5. [Quantify impact: $X per exploit cycle]

Severity Justification:
"While each individual flaw may be rated Medium, their combination 
enables [critical outcome] with [financial/data/access impact]. 
We rate this Critical per [program's] CVSS guidelines because 
Confidentiality/Integrity/Availability impact is HIGH with 
no privileges required beyond a standard user account."
```
