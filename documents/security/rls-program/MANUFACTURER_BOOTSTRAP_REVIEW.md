# Manufacturer authentication/bootstrap context review

This review resolves `decision-context-manufacturer-bootstrap` as architecture only. It creates no runtime implementation, SQL, RLS, role, grant, ownership, policy, function, database, infrastructure, staging or production change.

## Approved boundary

The primary boundary is `post-password-actor-bootstrap`. Manufacturer identity is verified after the exact password lookup returns one User, account activation checks pass and the password verifies. Signed session roots must revalidate their `userId` against the User row; refresh roots must also prove a current, non-revoked RefreshToken. Email and token/request role or tenant claims are not authority.

Manufacturers still require MFA before an active application session. Password assurance permits only the bounded membership bootstrap and MFA flow. Active tenant access and scope switching require `mfa-verified`.

## Current execution path and security problem

Current login calls `lookupPasswordBootstrapUser`, verifies the password, installs prototype context, then session construction calls `resolveManufacturerSessionScope` through the owning transaction. Session middleware and `/auth/me` revalidate the signed actor and call the same transaction-client-only resolver. Invitation setup still uses the separate richer `listManufacturerLicenseeLinks` helper.

The canonical session resolver has no global Prisma default, does not reuse JWT-carried membership, fails closed on missing, foreign, inactive, inconsistent, ambiguous or oversized membership, and returns no first-row fallback when multiple memberships have no primary. The richer invitation helper remains a separate runtime blocker because its admin mutation roots require their own transaction and command contract.

## Approved identity chain

1. `User.id` from the verified account row is the manufacturer identifier.
2. `User.role` must be MANUFACTURER, MANUFACTURER_ADMIN or MANUFACTURER_USER; request/JWT role is not authoritative.
3. User must be ACTIVE and active, with no disabled/deleted marker, a consumed account setup reflected by password/email verification, and valid authentication assurance.
4. `ManufacturerLicenseeLink.manufacturerId` must equal that User.id.
5. The linked Licensee must be active and unsuspended; its Organization must be active.
6. Licensee ID and organization ID come from the link and Licensee row. Non-null User tenant fields are consistency hints only and conflicting values fail closed.

`ManufacturerLicenseeLink` has no status, expiry or revocation columns. Today, row presence is active membership and row deletion is revocation. No temporal membership is inferred. Invitation rows stop being authority after account activation; INVITED, passwordless, unverified or inactive users cannot bootstrap.

## Minimum projection

The repository may return only:

| Field | Source | Reason |
|---|---|---|
| manufacturerUserId | User.id | Bind result to verified actor |
| accountRole | User.role | Install database role ceiling |
| licenseeId | ManufacturerLicenseeLink.licenseeId | Identify an eligible scope |
| organizationId | Licensee.orgId | Pair organization with that licensee |
| relationshipStatus | Computed ACTIVE after all predicates | Never expose an invalid membership |
| isPrimary | ManufacturerLicenseeLink.isPrimary | Deterministic initial selection |
| displayName | Licensee.name | Minimum selector label |
| scopeVersion | ManufacturerLicenseeLink.updatedAt | Detect stale selection |

Password/token hashes, MFA secrets, recovery codes, WebAuthn material, platform-admin state, email, full User/Licensee records, unrelated users and audit records are prohibited. Verification-only activation fields are checked but not returned.

## Multiple-licensee behaviour

Multiple active licensee links are supported. The query reads at most 101 rows and fails closed above 100 rather than truncating authority. Eligible results are ordered by `isPrimary DESC`, `createdAt ASC`, then `licenseeId ASC`.

- One eligible link is selected automatically.
- With several links and exactly one primary, the primary is selected.
- With several links and no primary, no tenant context is installed; the verified actor selects from the bounded returned set.
- Several primary links are an ambiguity failure, not a first-row choice.
- A client-supplied licensee ID only narrows a freshly re-read verified membership set. It never creates authority.

Scope switching requires an active `mfa-verified` session, exact membership and scopeVersion match, server request ID and purpose, a fresh transaction, and `MANUFACTURER_SCOPE_SWITCH` audit attribution.

## Context installation

The actor-bootstrap transaction installs verified `app.user_id`, `app.role`, `app.manufacturer_id`, `app.auth_assurance`, `app.request_id` and `app.purpose`. Licensee and organization values do not authorize reads before selection; blank values never mean all.

After server verification selects one relationship, a fresh transaction installs all eight canonical keys, with `app.licensee_id` and `app.organization_id` derived from the relationship. Query/body/JWT tenant values are never installed directly. Context is transaction-local and clears at transaction end.

## Failure semantics

No user, duplicate normalized user, invalid password, disabled/unactivated account and wrong role share non-enumerating authentication failure behaviour before actor proof. After password proof, missing membership, ambiguous primary state, foreign/revoked/disabled scope, legacy-field inconsistency, insufficient assurance, stale session, missing request ID, overflow and stale scopeVersion all deny context installation with the exact codes in `manufacturer-bootstrap-boundary.json`. No failure returns foreign membership details.

## Implementation decision

Use a transaction-client-only actor-context repository. A named pre-auth/security-definer function is not required because password or session verification already establishes User.id before the membership read. The future repository must use explicit projections, no global Prisma, no catch-to-empty authority fallback, bounded results, deterministic ordering, exact duplicate handling and same-transaction read attribution.

No production code is changed by this decision.

## Tests required

- Own manufacturer membership allowed; foreign manufacturer and foreign requested licensee denied.
- Missing/blank scope never means all; multiple memberships follow the exact primary/no-primary rules.
- User role comes from the database and role/tenant claims or body/query values cannot elevate it.
- Disabled User, Licensee or Organization, suspended Licensee and absent/revoked link are denied.
- Duplicate normalized User, multiple-primary membership, over-100 membership and stale scopeVersion fail closed.
- Exact projection excludes secret, platform-admin, unrelated-user and full-tenant fields.
- Actor context precedes every protected membership query and uses one supplied transaction client.
- Active scope switching requires MFA, request ID, purpose, fresh membership read, fresh transaction and audit.
- Invitation-created users remain denied until activation, password and email verification are complete.
- Disposable PostgreSQL proves actor-only link visibility, empty/forged/foreign denial and exact context installation.

## Workflow unlock analysis

`family-split-manufacturerscopeservice-manufacturer-id-scope-hydration-d04d198c46` now has exact semantics and is a focused future implementation candidate. It remains blocked by `manufacturer-bootstrap-runtime-pending` until the repository and tests exist.

`family-split-manufacturerscopeservice-manufacturer-link-auth-and-invite-407543caef` remains blocked. Only its authentication/bootstrap use is approved; invitation mutation must stop sharing the broad link reader or supply its own reviewed transaction boundary.

No broad login, session, invitation, user-hydration or manufacturer-linked route family is unlocked automatically. Existing optional/blank tenant route behaviour remains outside this decision.
