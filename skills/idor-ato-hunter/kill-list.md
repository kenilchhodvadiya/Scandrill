# IDOR/BOLA & ATO — Kill List

Do not report any of the following as IDOR or ATO. They wreck N/A ratios and
signal amateur output.

## ATO auto-rejects

1. **Theoretical `redirect_uri` accept, no code/token captured** — you showed
   the allowlist is loose but never actually landed a code/token on your
   host. Downgrade to config-hardening, not ATO.
2. **Missing `state` with no forced-linking or CSRF impact demonstrated** —
   the absence alone isn't a finding; show the login-CSRF or account-linking
   result.
3. **Self-service password reset working normally** — resetting your own
   password isn't ATO.
4. **Expired/already-invalidated token replay** — must be a live,
   unexpired token to count.
5. **JWT `alg:none` rejected by the server** — confirm the server actually
   accepts the unsigned token; a rejected attempt is not a finding.
6. **Username/email enumeration alone** — different response for
   valid-vs-invalid account is low severity by itself; only escalate if it
   feeds a reset-token brute-force or credential-stuffing chain.

## Auto-rejects

1. **Self-IDOR** — Reading your own data when authenticated as yourself.
   "I can read /api/users/me — that's an IDOR!" No, that's GET your-own.
2. **Public-by-design resource** — Reading a published event listing, a
   public blog post, a public profile that the product surfaces in
   directories. If the same body is reachable without auth, the bug is
   information disclosure (and usually intended).
3. **ID disclosure in URL with no follow-on** — `/checkout?order_id=12345`
   leaking the order_id to the next page isn't IDOR; only matters if the
   leaked ID can then be fetched cross-tenant.
4. **Org-admin reading their own org's data** — Admins in their own scope
   doing what admins do. The IDOR is *cross-org* or *cross-user-within-org*.
5. **Soft-deleted record visible to admins** — Admin-tier access pattern;
   not IDOR unless a low-priv user gets it.
6. **Account 1 happens to have superadmin** — Always test the reverse
   direction (A2→A1) too. If only A1→A2 works, A1 might just be
   support/admin/staff. Confirm symmetry.
7. **"Same row, different URL"** — A `/users/123` and `/u/123` returning
   the same record is route aliasing, not IDOR.
8. **403/404 cross-tenant** — That's authorization *working*. Don't write
   it up as "endpoint exists and returns an error."
9. **"Potential IDOR — needs further investigation"** — Confirm or kill.
   Never report unverified.
10. **GUID/UUID leak with no enumeration plan** — Knowing a UUID exists
    doesn't matter if you can't get to it. Find the leak path that gives
    you UUIDs at scale, then report.
11. **Stack-trace exposure** — Not IDOR. (Maybe info disclosure, but
    standalone usually <P3.)
12. **CSRF on a state-changing endpoint** — Different bug class. Don't
    pretend it's IDOR.
13. **Mass assignment of non-sensitive fields** — Setting `nickname`
    cross-user isn't IDOR. Setting `role`, `is_admin`, `tenant_id`,
    `balance`, `verified`, `email_verified`, `permissions` IS.

## Conditionally valid (chain or skip)

| Finding | Only valid if … |
|---|---|
| Cross-user read of `name` and `email` (non-PII-bulk) | Either at scale (1000s of users), OR chains to ATO (use the email for password-reset enumeration) |
| Cross-tenant read of metadata (no PII) | Tenant count or business-sensitive volume can be quantified |
| `/api/users/{id}` returns 200 for any id but the body is empty | Not IDOR until you find an endpoint that returns the body |
| Predictable invite/share URL | Only IDOR if you can use it to read resources you shouldn't, OR if invite carries elevated role |
| Cross-tenant access only when the second tenant is fresh / empty | Likely race-of-onboarding, not IDOR |
| Auth bypass via missing `Authorization` header on one endpoint | That's auth-bypass, file it as such |

## What changes a kill into a ship

| Kill reason | What promotes it |
|---|---|
| Self-read only | Add a second account; show A→B works |
| Only one direction | Show both directions OR explain why direction matters (e.g., support tier vs end-user) |
| Cross-user but trivial fields | Enumerate to scale OR chain to ATO |
| Cross-tenant but only 1 endpoint | Find the same root cause across multiple endpoints — it almost always exists |
| 403 cross-tenant on top-level route | Check sub-routes (`/{id}/edit`, `/{id}/refund`, `/{id}/export`) — *that's the Eventcube pattern* |
