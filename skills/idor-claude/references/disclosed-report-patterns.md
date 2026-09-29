# Disclosed-Report Patterns — BAC / IDOR / Privilege Escalation

Distilled from **112 rewarded** HackerOne reports (Improper Access Control, IDOR,
Privilege Escalation, Improper Authorization) — corpus of 416 rewarded reports,
$50–$35,000, sourced from `reddelexc/hackerone-reports` + the `hackerone.com/reports/<id>.json`
endpoint. These are the *actual* root causes that got paid. Apply them as extra Phase-5
hypotheses on any target. Each pattern: **what it is → how to test → real report IDs**.

Load this when: mapping authz surface, generating hypotheses, or stuck for ideas mid-hunt.

---

## Ranked by frequency in the corpus (test in this order)

### 1. Undocumented / hidden GraphQL operation, no permission check ⭐ highest-yield
Staff/member with **zero permissions** calls a mutation/query that the UI never exposes to
them. The resolver checks nothing. This single pattern paid out repeatedly on Shopify.
- **Test:** grep JS bundles + proxy history for GraphQL `operationName`s. For every mutation
  you can name (`*Update`, `*Create`, `*Export`, `*Copy`, `*Delete`, `*Publish`), replay it
  from a **no-permission staff / low-role** session. A `Not found` (vs `Access denied`) reply
  = the resolver *ran* and only missed the object → the check is on object existence, not authz.
- **Real:** `emailSenderConfigurationUpdate` (980511), `fileCopy` (981472), `billingChargesExport`
  (1010835), billing-promotion accept (1044869), `webhookSubscriptionCreate BULK_OPERATIONS_FINISH`
  (1350095), `GitHubRepositoriesQuery` reads any user's private repos (1692788), `ThemePublishLegacy`
  publish paid theme free (927567, 953083).

### 2. Predictable/incremental ID in a **mutation** → cross-user write/delete
Not just read. The big payouts are *destructive* IDOR: change the numeric/short ID in a
delete/edit mutation and it hits everyone.
- **Test:** on every write op, swap the object ID to a foreign one AND walk the ID space
  (incremental = whole-platform). Confirm with a second account's real record in the response.
- **Real:** Snapchat `DeleteStorySnaps{ids}` delete anyone's spotlight (1819832, $15k),
  H1 `CreateOrUpdateHackerCertification` delete all users' licenses (2122671, $12.5k),
  RedditGifts delete all 4.4M DMs via DELETE msg id (1213237), Shopify `BillingDocumentDownload`/
  `BillDetails` incremental invoice id dumps every merchant's PII (2207248, 5000-IDOR),
  GitLab ML Model Registry incremental id (2528293), judge.me `comment_id` leaks buyer email (1410498).

### 3. Per-verb / per-interface authz gap (check exists on read, not on write — or on UI, not API)
The ownership check is implemented on *some* operations/surfaces of a resource but not all.
- **Test:** for a resource that 403s in the UI or on GET, retry every sibling: the **REST/GraphQL
  API**, `DELETE`, `PUT`, `/edit`, `/notes`, `/export`, `/duplicate`, older API versions (`/v1`).
- **Real:** demoted-to-Guest user still reads/edits his MR via `/api/.../merge_requests` while UI
  blocks it (962604); polymorphic switch — change `noteable_type` from `issue`→`personal_snippet`
  so the project scope check is skipped on note creation (1751258); Order Printer app reads orders
  for a member with no Orders permission because the app never verifies user privileges (64164).

### 4. Mass-assignment of a role / admin / owner field
Send `{"admin":true}` or a `role`/`is_admin`/`permission` param the UI never offers.
- **Test:** in any "update profile / member / account" request, add or flip a privilege field.
  Content-Type sometimes must be JSON for it to bind (see 42961).
- **Real:** fabric.io member→admin via `PUT /accounts/<id> {"admin":true}` (42961); fabric.io admin
  deletes other apps' members by swapping account+app id and dropping `admin=` (43065); TaxJar member
  invites self as admin via `/current_user_data` (1677541); access-list owner escalates to highest
  role (2281075).

### 5. UI hides the privileged action, backend endpoint is wide open (forced request)
Feature shown only to owner; low-priv user replays the raw request and it works.
- **Test:** log the **owner's** request for owner-only settings (login services, tax, themes,
  billing), then replay it verbatim from a low-priv/staff session (fix CSRF token + cookies only).
- **Real:** shop admin changes external login/OAuth services owner-only (56626); tax-override
  `collection_id` with no ShopID check adds any/ hidden collection (93004); staff w/ only `Customers`
  perm reads full orders via chat-app link (1392032).

### 6. Guest/low role performs Reporter+/Developer+ action via parameter tamper
Role gating is enforced on the obvious path only; a crafted request skips it.
- **Test:** as the lowest role, take a higher-role action's request and change a type/param.
- **Real:** GitLab Guest creates a `test_case` by changing `issue[issue_type]` (1113289); Guest
  creates Sentry error-tracking issues (1117768); Reporter uploads Design files via issue "Move to"
  (1112297).

### 7. Approval / moderation step bypass by replaying or flipping status
The "pending → approved" gate lives only in the happy-path UI flow.
- **Test:** capture the final submit; re-send it with `status=ACTIVE`/`state=approved`/
  `reply_action=agree-*`, or re-send the create after the approval would happen.
- **Real:** inDriver `UpdateVacancyStatus` status→`ACTIVE` skips admin approval (1861487);
  H1 hacker self-publishes report bypassing moderator (452959).

### 8. Email-field injection → bypass verification → accept invites / take over
Adding an `email` param marks it verified, or an invite is accepted without owning the mailbox.
- **Test:** on signup/email-change/invite-accept, inject `email=<target>` or accept an invite
  without clicking the emailed link; check if an unverified account can accept team invites.
- **Real:** add `email` to bypass verification and hijack ads-team invites as others (1551176);
  Shopify Partners invite needs no email verification → priv esc (2885269); ATO via billing sets
  target's empty email then password-reset (394329).

### 9. Import / export / template = trust boundary hole
Import parsers trust foreign keys, `template:true`, URLs, and namespaces from the uploaded file.
- **Test:** export an object, edit the JSON/tarball (inject `*_ids`, `template`, `file://` URL,
  `target_namespace`), re-import. Watch for cross-object linkage or SSRF/local read.
- **Real:** GitLab import injects `issue_ids`/`merge_request_ids` to steal private objects
  (743953, 767770); import sets `template:true` service to mutate all projects (446585); project
  template copies private repo/issues (689314); `file://` import reads local repos (1685822, $22.3k);
  GitHub import creates child group under a namespace you can't access (301137).

### 10. Cross-tenant via missing tenant/owner scope on a shared or global resource
No `ShopID`/`org_id`/tenant filter, or a token from one channel works on another.
- **Test:** supply a foreign tenant's object id with your own session; check both directions.
- **Real:** city-mobil cross-org data (863983); LINE Notification channel accepts another channel's
  token (1314162); Argo CD reconciles apps outside allowed namespaces when sharding on (1847140);
  tax-override no ShopID (93004).

---

## Auth-flow & session patterns (ATO-grade)

- **Password reset — parameter/content-type pollution.** GET query overrides POST body
  (96636); convert form → JSON so `user[email]` becomes an array and the reset link returns to you
  (GitLab, 2293343, **$35k** — the single highest). Reset link over plain HTTP (1888915).
- **OAuth `redirect_uri` / code theft.** Path traversal in `redirect_uri` leaks auth code via
  the attacker product page + analytics (1861974); service worker intercepts `/auth` to steal Pages
  tokens (1439552); `postMessage` `targetOrigin` starting with `window` steals access token (821896).
- **OTP / 2FA bypass.** Change `number`+`resId` so OTP comes to *you*, then claim the victim
  restaurant (1330529); TikTok 2FA bypass via seller-URL redirect (1247108); 2FA *requirement*
  bypassed by using the program's embedded submission form (418767).

## Recon-driven access control (no second account needed)

- **Leaked UUID via wayback/gau → query "private" object.** Embedded-form UUIDs harvested from
  `waybackurls` still resolve private program data via GraphQL (2483666). Always feed old URLs the
  ID scheme you found back into current endpoints.
- **Exposed admin/CI/proxy with no or fake auth.** `admin.php` open (1417288); CI page where the
  "Log in" button needs no auth, leaking deploy creds (311289); open proxy → internal domains
  (2967634, $7.5k); unauth vendor site → Uber tax docs (530441).
- **Discoverability / privacy toggle bypass.** Twitter phone/email → Twitter ID via Android
  duplicate-check even with discoverability off (1439026); LINE hidden-friends via internal id
  (853894); public employee Google Calendar leaks meetings/PII (489284); private file made public
  via image transformations (1984060) or Diffusion commit attach (1560717).

## Blocked / revoked / scoped-down actors still act

- Blocked user keeps git access via a still-valid CI/CD token (497047); demoted user via API
  (962604); a **scoped** app-token edits its own scope via `PUT` to gain full access (1193321);
  malicious admin permanently locks the owner out (1718574).

## Infra / local privilege escalation (out of web-IDOR scope, but same category pays)
Note for triage only — these need host/binary access, not a web session: Apache LPE (520903),
Linux eBPF verifier LPE (1010340), Steam/VeraCrypt arbitrary-write-as-SYSTEM (583184, 530292),
kOps/ingress-nginx serviceaccount-token theft → cluster-admin (1842829, 1382919), container escape
via symlinked build logs (694181, 697055), PS4 BD-J chains (1379975, 3452696), headless-Chromium
`--no-sandbox` RCE via reporting (1168765). If the program scope is web/API, don't chase these.

---

## What the corpus proves about *impact* (for Phase 7 escalation)

1. **Incremental ID + any cross-object primitive = whole-platform**, and disclosed reports pay
   most when the write is *destructive* (delete/overwrite) or *financial* (billing/invoice/theme).
2. **"Staff with no permissions" on a SaaS admin is a first-class attacker** — enumerate every
   GraphQL op against that role; missing checks there are routine and paid $600–$2000 each.
3. **`Not found` ≠ safe.** It often means the authz check is really an existence check — try a
   valid foreign id.
4. Big ATO money is in **reset/verify/invite/OAuth** flows, not raw object IDs.

Cross-refs: `playbooks/graphql.md` (undocumented ops, nested resolvers), `playbooks/rest-api.md`
(per-verb + version downgrade), `playbooks/multi-tenant-saas.md` (invite/token/tenant boundary),
`references/id-schemes.md` (enumerability), `escalation-gate.md` (Phase 7 chain proof).
