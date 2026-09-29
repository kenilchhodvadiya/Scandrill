# API BLF — REST / GraphQL / gRPC / WebSocket

## REST API BLF Patterns

### HTTP Method Confusion
```
□ GET /admin/users → try PUT /admin/users (mass update without auth)
□ PATCH instead of PUT → partial update bypasses full validation
□ DELETE on resource you don't own → check IDOR
□ HEAD request → may skip auth checks that only apply to GET
□ OPTIONS → reveals hidden endpoints, allowed methods
```

### Parameter Pollution
```
□ Duplicate params: amount=100&amount=0 → server uses first or last
□ Array injection: price[]=0&price[]=100 → parser confusion
□ JSON vs form: same endpoint, different parser, different validation
□ Encoding bypass: amount=%30 (URL-encoded "0"), amount=\u0030
□ Type coercion: "price": "0" vs "price": 0 — string vs integer
□ Null injection: "role": null → treated as missing → default to admin?
```

### Versioning & Shadow APIs
```
□ /api/v3/ current → /api/v1/ still live with weaker validation
□ /api/v2/checkout → /api/v1/checkout with no price validation
□ /api/internal/ → accessible without external auth
□ /api/admin/ → accessible with regular user token
□ /api/debug/ → test endpoints left in production
□ Mobile API vs web API: mobile endpoints often have weaker controls
```

### ID & Reference Manipulation
```
□ Sequential IDs: order_id=1001 → try 1000, 999 (other users' orders)
□ UUID prediction: UUID v1 is timestamp-based → enumerate
□ GUID reuse: deleted resource GUID → create new resource with same GUID
□ Reference substitution: use your object_id in another user's workflow
□ Cross-tenant: org_id in request → change to other org's ID
```

## GraphQL BLF

### Introspection Abuse
```
# Always try:
{ __schema { types { name fields { name } } } }

# Look for:
- adminMutation, internalQuery, debugField
- Hidden arguments (role, is_admin, override)
- Deprecated but still-live fields
```

### GraphQL-Specific Attacks
```
□ Alias multiplication: query same field 1000x in one request (DoS/rate limit bypass)
□ Query batching: [{"query": "mutation {...}"}, ...] × 100 (race via batch)
□ Nested query DoS: deeply nested relationships → exponential data fetch
□ Field suggestion: type "admin" → server suggests "adminUser" (info disclosure)
□ Mutation without auth: mutations sometimes miss auth checks vs queries
□ Subscription: subscribe to other users' events via WebSocket
□ Variables injection: pass role/permissions via GraphQL variables
```

### GraphQL BLF Test Cases
```graphql
# 1. Privilege escalation via mutation
mutation {
  updateUser(id: "victim_id", role: "admin") {
    id role
  }
}

# 2. Price manipulation
mutation {
  checkout(items: [{id: "123", price: 0.01}]) {
    orderId total
  }
}

# 3. IDOR via query
query {
  order(id: "other_user_order_id") {
    id total items { name }
  }
}

# 4. Batch race for coupon
[
  {"query": "mutation { redeemCoupon(code: \"SAVE50\") { success } }"},
  {"query": "mutation { redeemCoupon(code: \"SAVE50\") { success } }"},
  ...repeat 20x
]
```

## gRPC BLF

```
□ Use grpcurl or grpc-web interceptor (Burp with grpc-web plugin)
□ Protobuf field manipulation: unknown fields, wrong types
□ Service reflection: grpcurl list target:443 → discover hidden services
□ Method auth: some RPC methods skip auth middleware
□ Field 0 or MAX: proto field with value 0 vs absent = different behavior
□ Enum out of range: send integer beyond defined enum values
□ Repeated field abuse: send 10000 items in a repeated field
```

## WebSocket BLF

```
□ Auth check only on connection → send privileged messages post-connect
□ Message replay: capture and replay purchase confirmation
□ Room/channel IDOR: subscribe to another user's private channel
□ Message injection: craft messages that affect other users' state
□ Disconnect race: disconnect during transaction → partial state
□ Cross-channel: send message to admin channel via user WebSocket
```

## API Rate Limiting & Quota BLF

```
□ Rate limit per IP → rotate with X-Forwarded-For header
□ Rate limit per user → use multiple accounts simultaneously
□ Quota check before action: race to act before quota registers
□ Burst allowance: send 99 requests/sec on 100/sec limit
□ Endpoint aliasing: /api/users and /api/users/ are different endpoints
□ Method bypass: rate limit on POST but not PUT for same action
□ Param-based limit: limit on coupon_code field → null/empty bypass
□ 429 bypass: change Content-Type, add trailing slash, change case
```

## Webhook & Async BLF

```
□ Webhook replay: resend payment_success event → duplicate fulfillment
□ SSRF via webhook URL: register webhook pointing to internal service
□ Webhook signature skip: remove HMAC header → still processed
□ Async race: POST action → async processing → send duplicate before completion
□ Callback manipulation: modify callback_url in payment initiation
□ Event order: deliver events out of order → invalid state
□ Idempotency key: reuse idempotency key with different payload
```
