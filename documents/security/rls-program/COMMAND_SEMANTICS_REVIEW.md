# MSCQR full-database command semantics review

This is the compact human review of `command-semantics.json`. It defines architecture only: no SQL, grants, roles, RLS state, or runtime behavior are changed.

Rules: 988; workflows mapped: 428/428.

## Review groups

| Group | Tables | Rules | SELECT | INSERT | UPDATE | DELETE |
|---|---:|---:|---:|---:|---:|---:|
| A | 21 | 222 | 94 | 37 | 65 | 26 |
| B | 3 | 66 | 33 | 15 | 13 | 5 |
| C | 15 | 241 | 135 | 27 | 61 | 18 |
| D | 13 | 266 | 134 | 43 | 73 | 16 |
| E | 18 | 161 | 71 | 44 | 26 | 20 |
| F | 7 | 32 | 9 | 8 | 7 | 8 |
| G | 0 | 0 | 0 | 0 | 0 | 0 |

## Actor classes

| Value | Rules |
|---|---:|
| anonymous | 19 |
| authenticated-user | 291 |
| manufacturer | 239 |
| operator | 100 |
| checker | 10 |
| licensee-admin | 139 |
| platform-admin | 232 |
| restricted-read | 16 |
| pre-auth-runtime | 19 |
| worker | 5 |
| scheduled-job | 10 |
| migration | 2 |
| operator-admin | 81 |
| break-glass | 7 |

## Assurance levels

| Value | Rules |
|---|---:|
| none | 94 |
| password-verified | 507 |
| mfa-bootstrap | 3 |
| mfa-verified | 248 |
| step-up-verified | 15 |
| system-verified | 33 |
| operator-approved | 81 |
| dual-approved-break-glass | 7 |

## Commands

| Value | Rules |
|---|---:|
| SELECT | 476 |
| INSERT | 174 |
| UPDATE | 245 |
| DELETE | 93 |

## Boundary and deletion summary

Named-function rules: 339.
Restricted-worker rules: 15.
Approval-gated rules: 101.

| Hard-delete classification | Rules |
|---|---:|
| actor self-delete | 5 |
| migration-only | 3 |
| not-applicable | 895 |
| operator-approved | 1 |
| prohibited | 75 |
| retention delete | 3 |
| tenant-admin delete | 6 |

Lifecycle restrictions are carried per rule; Batch rules name the approved DRAFT through RELEASED transition states and terminal FAILED/VOIDED denials. Other state-bearing tables require their canonical service transition before a write can satisfy the rule.

