# MSCQR full-database command semantics review

This is the compact human review of `command-semantics.json`. It defines architecture only: no SQL, grants, roles, RLS state, or runtime behavior are changed.

Rules: 999; workflows mapped: 401/401.

## Review groups

| Group | Tables | Rules | SELECT | INSERT | UPDATE | DELETE |
|---|---:|---:|---:|---:|---:|---:|
| A | 22 | 219 | 109 | 27 | 55 | 28 |
| B | 3 | 66 | 60 | 1 | 2 | 3 |
| C | 15 | 242 | 148 | 20 | 56 | 18 |
| D | 13 | 252 | 132 | 36 | 70 | 14 |
| E | 18 | 169 | 80 | 47 | 24 | 18 |
| F | 7 | 51 | 11 | 25 | 7 | 8 |
| G | 0 | 0 | 0 | 0 | 0 | 0 |

## Actor classes

| Value | Rules |
|---|---:|
| anonymous | 57 |
| authenticated-user | 326 |
| manufacturer | 315 |
| operator | 71 |
| checker | 7 |
| licensee-admin | 200 |
| platform-admin | 236 |
| restricted-read | 16 |
| pre-auth-runtime | 57 |
| worker | 6 |
| scheduled-job | 19 |
| migration | 0 |
| operator-admin | 1 |
| break-glass | 0 |

## Assurance levels

| Value | Rules |
|---|---:|
| none | 133 |
| password-verified | 610 |
| mfa-bootstrap | 5 |
| mfa-verified | 199 |
| step-up-verified | 7 |
| system-verified | 41 |
| operator-approved | 4 |
| dual-approved-break-glass | 0 |

## Commands

| Value | Rules |
|---|---:|
| SELECT | 540 |
| INSERT | 156 |
| UPDATE | 214 |
| DELETE | 89 |

## Boundary and deletion summary

Named-function rules: 462.
Restricted-worker rules: 25.
Approval-gated rules: 9.

| Hard-delete classification | Rules |
|---|---:|
| actor self-delete | 8 |
| not-applicable | 910 |
| prohibited | 76 |
| retention delete | 1 |
| tenant-admin delete | 4 |

Lifecycle restrictions are carried per rule; Batch rules name the approved DRAFT through RELEASED transition states and terminal FAILED/VOIDED denials. Other state-bearing tables require their canonical service transition before a write can satisfy the rule.

