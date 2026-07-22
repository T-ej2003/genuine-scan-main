# MSCQR full-database command semantics review

This is the compact human review of `command-semantics.json`. It defines architecture only: no SQL, grants, roles, RLS state, or runtime behavior are changed.

Rules: 988; workflows mapped: 401/401.

## Review groups

| Group | Tables | Rules | SELECT | INSERT | UPDATE | DELETE |
|---|---:|---:|---:|---:|---:|---:|
| A | 21 | 211 | 106 | 26 | 52 | 27 |
| B | 3 | 66 | 60 | 1 | 2 | 3 |
| C | 15 | 242 | 148 | 20 | 56 | 18 |
| D | 13 | 252 | 132 | 36 | 70 | 14 |
| E | 18 | 169 | 80 | 47 | 24 | 18 |
| F | 7 | 48 | 9 | 24 | 7 | 8 |
| G | 0 | 0 | 0 | 0 | 0 | 0 |

## Actor classes

| Value | Rules |
|---|---:|
| anonymous | 57 |
| authenticated-user | 325 |
| manufacturer | 315 |
| operator | 67 |
| checker | 7 |
| licensee-admin | 199 |
| platform-admin | 235 |
| restricted-read | 16 |
| pre-auth-runtime | 57 |
| worker | 5 |
| scheduled-job | 15 |
| migration | 0 |
| operator-admin | 1 |
| break-glass | 0 |

## Assurance levels

| Value | Rules |
|---|---:|
| none | 132 |
| password-verified | 608 |
| mfa-bootstrap | 5 |
| mfa-verified | 199 |
| step-up-verified | 7 |
| system-verified | 36 |
| operator-approved | 1 |
| dual-approved-break-glass | 0 |

## Commands

| Value | Rules |
|---|---:|
| SELECT | 535 |
| INSERT | 154 |
| UPDATE | 211 |
| DELETE | 88 |

## Boundary and deletion summary

Named-function rules: 446.
Restricted-worker rules: 20.
Approval-gated rules: 9.

| Hard-delete classification | Rules |
|---|---:|
| actor self-delete | 8 |
| not-applicable | 900 |
| prohibited | 75 |
| retention delete | 1 |
| tenant-admin delete | 4 |

Lifecycle restrictions are carried per rule; Batch rules name the approved DRAFT through RELEASED transition states and terminal FAILED/VOIDED denials. Other state-bearing tables require their canonical service transition before a write can satisfy the rule.

