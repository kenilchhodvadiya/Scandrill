# Web App BLF — Deep Reference

## CMS-Specific BLF

### WordPress / WooCommerce
```
□ WooCommerce coupon: apply coupon → change cart → coupon stays on checkout
□ Product price: price stored client-side in hidden field → tamper
□ Subscription: cancel → reactivate without payment via order status change
□ User role: change role=subscriber to role=administrator in profile update
□ Download: purchase digital product → manipulate download_id IDOR
□ Refund: WooCommerce refund endpoint race condition
□ Gift card plugin: generate codes via predictable pattern
□ Multi-vendor: vendor A access vendor B orders via order_id IDOR
□ Membership: expiry date in user_meta → modify via profile endpoint
```

### Shopify Apps & Storefronts
```
□ Discount: draft_order API with manual discount → bypass validation
□ Cart attributes: hidden cart attributes controlling price
□ Checkout token: reuse checkout token across different sessions
□ Inventory: negative inventory oversell via API
□ Wholesale pricing: access wholesale endpoint as retail customer
□ App webhooks: replay payment webhooks for duplicate fulfillment
□ Multipass: forge Multipass token if secret is exposed
□ Storefront API: access admin-only product data via storefront token
```

### Magento / Adobe Commerce
```
□ Quote manipulation: modify quote_id price via REST API
□ Catalog price rule: trigger incorrectly scoped discount
□ Reward points: race on redemption, negative point balance
□ Customer group: change customer_group_id for B2B pricing
□ Admin panel: cached admin session after role downgrade
□ Gift registry: transfer registry items without auth
```

### Laravel / Django / Rails Apps
```
□ Mass assignment: POST with extra fields (role, is_admin, confirmed)
□ Route model binding: predict sequential IDs for unauthorized access
□ Soft delete: access soft-deleted records via direct ID
□ Scope bypass: tenant isolation broken → cross-tenant data access
□ Enum coercion: send string for enum field → unexpected branch
```

## Auth & Session Logic

### Multi-Step Auth Flows
```
□ Step 1 complete (username+pass) → skip 2FA → direct to /dashboard
□ Password reset: request reset for victim → use token for your account
□ Email OTP: OTP valid for 10 min, no brute-force protection → enumerate
□ TOTP: clock skew allows ±1 window → extend valid window
□ Account recovery: security questions with no lockout
□ Magic link: link works after password change (old link not invalidated)
```

### OAuth Logic
```
□ state parameter missing/not validated → CSRF login
□ redirect_uri: open redirect via subdomain/path confusion
□ Token scope: request narrow scope → server issues broad scope
□ Authorization code reuse: code not invalidated after first use
□ Implicit flow: access_token in fragment → referer leak
□ Account linking: link attacker OAuth account to victim account
```

## E-Commerce Deep Patterns

### Cart & Checkout
```
TEST SEQUENCE (run in this order):
1. Map the full checkout flow (cart → shipping → payment → confirm)
2. Attempt direct POST to /checkout/confirm without prior steps
3. Intercept final payment request → modify amount/currency
4. Add item → apply coupon → remove item → keep coupon for new items
5. quantity=-1 or quantity=0.5 or quantity=99999999
6. price=0.00, price=-100, price=0.001
7. currency=XXX (invalid), currency swap USD→EUR with favorable rate
8. POST to /order/complete with order_id of another user's pending order
```

### Refund & Return Logic
```
□ Refund without return confirmation (skip return step)
□ Refund for item never delivered (no delivery verification)
□ Double refund: race two refund requests for same order
□ Partial refund exceeding order total
□ Refund to different payment method than original
□ Refund after chargeback (double recovery)
□ Gift card purchase → refund to original payment → gift card still valid
```

## SaaS Specific

### Seat & License Logic
```
□ Create team → add 1 seat → API: PUT /seats {"count": 1000}
□ Add member → race to exceed seat limit before check completes
□ Remove member → seat freed → re-add → never charged for extra month
□ Transfer seat to unverified user → inherit premium features
□ API key from premium account → use on free account's API calls
```

### Feature Flag Abuse
```
□ JavaScript: search for feature flags in JS bundles
□ Request: X-Feature-Flag: enterprise_export → try enabling
□ Cookie: featureFlags={"ai_assist": true} → modify JSON
□ URL parameter: ?beta=true, ?preview=enterprise
□ Request body: add {"features": ["advanced_analytics"]}
□ Response manipulation: change feature_enabled: false → true (then test if server validates)
```

### Trial & Subscription
```
□ Trial end date in JWT claim → modify expiry
□ Trial reset: create new account with same payment method
□ Subscription cancel → still access premium for billing period → race at expiry
□ Proration: downgrade → immediate upgrade → get premium at lower rate
□ Invoice manipulation: modify invoice amount before payment processing
```
