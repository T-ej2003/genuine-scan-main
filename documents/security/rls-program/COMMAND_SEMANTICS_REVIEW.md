# MSCQR full-database command semantics review

This is the compact human review of `command-semantics.json`. It defines architecture only: no SQL, grants, roles, RLS state, or runtime behavior are changed.

Rules: 946; workflows mapped: 400/400.

## Review groups

| Group | Tables | Rules | SELECT | INSERT | UPDATE | DELETE |
|---|---:|---:|---:|---:|---:|---:|
| A | 21 | 188 | 89 | 24 | 48 | 27 |
| B | 3 | 56 | 50 | 1 | 2 | 3 |
| C | 15 | 242 | 148 | 20 | 56 | 18 |
| D | 13 | 252 | 132 | 36 | 70 | 14 |
| E | 18 | 170 | 78 | 49 | 25 | 18 |
| F | 7 | 38 | 7 | 17 | 6 | 8 |
| G | 0 | 0 | 0 | 0 | 0 | 0 |

## Actor classes

| Value | Rules |
|---|---:|
| anonymous | 41 |
| authenticated-user | 312 |
| manufacturer | 315 |
| operator | 67 |
| checker | 7 |
| licensee-admin | 194 |
| platform-admin | 227 |
| restricted-read | 16 |
| pre-auth-runtime | 41 |
| worker | 5 |
| scheduled-job | 10 |
| migration | 0 |
| operator-admin | 1 |
| break-glass | 0 |

## Assurance levels

| Value | Rules |
|---|---:|
| none | 116 |
| password-verified | 598 |
| mfa-bootstrap | 5 |
| mfa-verified | 188 |
| step-up-verified | 7 |
| system-verified | 31 |
| operator-approved | 1 |
| dual-approved-break-glass | 0 |

## Commands

| Value | Rules |
|---|---:|
| SELECT | 504 |
| INSERT | 147 |
| UPDATE | 207 |
| DELETE | 88 |

## Boundary and deletion summary

Named-function rules: 403.
Restricted-worker rules: 15.
Approval-gated rules: 9.

| Hard-delete classification | Rules |
|---|---:|
| actor self-delete | 8 |
| not-applicable | 858 |
| prohibited | 75 |
| retention delete | 1 |
| tenant-admin delete | 4 |

Lifecycle restrictions are carried per rule; Batch rules name the approved DRAFT through RELEASED transition states and terminal FAILED/VOIDED denials. Other state-bearing tables require their canonical service transition before a write can satisfy the rule.

