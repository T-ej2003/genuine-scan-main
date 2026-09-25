# MSCQR full-database command semantics review

This is the compact human review of `command-semantics.json`. It defines architecture only: no SQL, grants, roles, RLS state, or runtime behavior are changed.

Rules: 1450; workflows mapped: 330/330.

## Review groups

| Group | Tables | Rules | SELECT | INSERT | UPDATE | DELETE |
|---|---:|---:|---:|---:|---:|---:|
| A | 24 | 492 | 321 | 37 | 102 | 32 |
| B | 3 | 210 | 195 | 6 | 4 | 5 |
| C | 15 | 235 | 155 | 21 | 42 | 17 |
| D | 13 | 141 | 70 | 19 | 38 | 14 |
| E | 18 | 246 | 115 | 87 | 26 | 18 |
| F | 7 | 126 | 29 | 70 | 19 | 8 |
| G | 0 | 0 | 0 | 0 | 0 | 0 |

## Actor classes

| Value | Rules |
|---|---:|
| anonymous | 95 |
| authenticated-user | 601 |
| manufacturer | 228 |
| operator | 247 |
| checker | 6 |
| licensee-admin | 372 |
| platform-admin | 477 |
| restricted-read | 16 |
| pre-auth-runtime | 95 |
| worker | 6 |
| scheduled-job | 21 |
| migration | 4 |
| operator-admin | 1 |
| break-glass | 0 |

## Assurance levels

| Value | Rules |
|---|---:|
| none | 173 |
| password-verified | 887 |
| mfa-bootstrap | 0 |
| mfa-verified | 314 |
| step-up-verified | 25 |
| system-verified | 47 |
| operator-approved | 4 |
| dual-approved-break-glass | 0 |

## Commands

| Value | Rules |
|---|---:|
| SELECT | 885 |
| INSERT | 240 |
| UPDATE | 231 |
| DELETE | 94 |

## Boundary and deletion summary

Named-function rules: 1102.
Restricted-worker rules: 27.
Approval-gated rules: 8.

| Hard-delete classification | Rules |
|---|---:|
| actor self-delete | 9 |
| not-applicable | 1356 |
| operator-approved | 1 |
| prohibited | 78 |
| retention delete | 1 |
| tenant-admin delete | 5 |

Lifecycle restrictions are carried per rule; Batch rules name the approved DRAFT through RELEASED transition states and terminal FAILED/VOIDED denials. Other state-bearing tables require their canonical service transition before a write can satisfy the rule.

