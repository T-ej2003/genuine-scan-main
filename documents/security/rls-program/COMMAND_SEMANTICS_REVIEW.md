# MSCQR full-database command semantics review

This is the compact human review of `command-semantics.json`. It defines architecture only: no SQL, grants, roles, RLS state, or runtime behavior are changed.

Rules: 974; workflows mapped: 428/428.

## Review groups

| Group | Tables | Rules | SELECT | INSERT | UPDATE | DELETE |
|---|---:|---:|---:|---:|---:|---:|
| A | 21 | 222 | 94 | 37 | 65 | 26 |
| B | 3 | 66 | 33 | 15 | 13 | 5 |
| C | 15 | 241 | 135 | 27 | 61 | 18 |
| D | 13 | 266 | 134 | 43 | 73 | 16 |
| E | 18 | 149 | 66 | 38 | 25 | 20 |
| F | 7 | 30 | 9 | 7 | 6 | 8 |
| G | 0 | 0 | 0 | 0 | 0 | 0 |

## Actor classes

| Value | Rules |
|---|---:|
| anonymous | 27 |
| authenticated-user | 280 |
| manufacturer | 235 |
| operator | 102 |
| checker | 10 |
| licensee-admin | 137 |
| platform-admin | 226 |
| restricted-read | 16 |
| pre-auth-runtime | 27 |
| worker | 7 |
| scheduled-job | 2 |
| migration | 2 |
| operator-admin | 79 |
| break-glass | 9 |

## Assurance levels

| Value | Rules |
|---|---:|
| none | 99 |
| password-verified | 508 |
| mfa-bootstrap | 3 |
| mfa-verified | 239 |
| step-up-verified | 10 |
| system-verified | 27 |
| operator-approved | 79 |
| dual-approved-break-glass | 9 |

## Commands

| Value | Rules |
|---|---:|
| SELECT | 471 |
| INSERT | 167 |
| UPDATE | 243 |
| DELETE | 93 |

## Boundary and deletion summary

Named-function rules: 344.
Restricted-worker rules: 9.
Approval-gated rules: 101.

| Hard-delete classification | Rules |
|---|---:|
| actor self-delete | 5 |
| migration-only | 3 |
| not-applicable | 881 |
| operator-approved | 1 |
| prohibited | 75 |
| retention delete | 3 |
| tenant-admin delete | 6 |

Lifecycle restrictions are carried per rule; Batch rules name the approved DRAFT through RELEASED transition states and terminal FAILED/VOIDED denials. Other state-bearing tables require their canonical service transition before a write can satisfy the rule.

