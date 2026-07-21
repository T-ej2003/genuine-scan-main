# MSCQR full-database command semantics review

This is the compact human review of `command-semantics.json`. It defines architecture only: no SQL, grants, roles, RLS state, or runtime behavior are changed.

Rules: 1069; workflows mapped: 428/428.

## Review groups

| Group | Tables | Rules | SELECT | INSERT | UPDATE | DELETE |
|---|---:|---:|---:|---:|---:|---:|
| A | 21 | 240 | 108 | 38 | 66 | 28 |
| B | 3 | 95 | 62 | 15 | 13 | 5 |
| C | 15 | 247 | 141 | 27 | 61 | 18 |
| D | 13 | 266 | 134 | 43 | 73 | 16 |
| E | 18 | 183 | 83 | 54 | 26 | 20 |
| F | 7 | 38 | 9 | 14 | 7 | 8 |
| G | 0 | 0 | 0 | 0 | 0 | 0 |

## Actor classes

| Value | Rules |
|---|---:|
| anonymous | 47 |
| authenticated-user | 281 |
| manufacturer | 316 |
| operator | 89 |
| checker | 10 |
| licensee-admin | 230 |
| platform-admin | 283 |
| restricted-read | 16 |
| pre-auth-runtime | 47 |
| worker | 5 |
| scheduled-job | 10 |
| migration | 2 |
| operator-admin | 81 |
| break-glass | 7 |

## Assurance levels

| Value | Rules |
|---|---:|
| none | 122 |
| password-verified | 579 |
| mfa-bootstrap | 4 |
| mfa-verified | 228 |
| step-up-verified | 15 |
| system-verified | 33 |
| operator-approved | 81 |
| dual-approved-break-glass | 7 |

## Commands

| Value | Rules |
|---|---:|
| SELECT | 537 |
| INSERT | 191 |
| UPDATE | 246 |
| DELETE | 95 |

## Boundary and deletion summary

Named-function rules: 433.
Restricted-worker rules: 15.
Approval-gated rules: 101.

| Hard-delete classification | Rules |
|---|---:|
| actor self-delete | 7 |
| migration-only | 3 |
| not-applicable | 974 |
| operator-approved | 1 |
| prohibited | 75 |
| retention delete | 3 |
| tenant-admin delete | 6 |

Lifecycle restrictions are carried per rule; Batch rules name the approved DRAFT through RELEASED transition states and terminal FAILED/VOIDED denials. Other state-bearing tables require their canonical service transition before a write can satisfy the rule.

