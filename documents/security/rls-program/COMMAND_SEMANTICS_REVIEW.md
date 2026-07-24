# MSCQR full-database command semantics review

This is the compact human review of `command-semantics.json`. It defines architecture only: no SQL, grants, roles, RLS state, or runtime behavior are changed.

Rules: 1351; workflows mapped: 338/338.

## Review groups

| Group | Tables | Rules | SELECT | INSERT | UPDATE | DELETE |
|---|---:|---:|---:|---:|---:|---:|
| A | 23 | 431 | 259 | 35 | 107 | 30 |
| B | 3 | 202 | 187 | 6 | 4 | 5 |
| C | 15 | 232 | 151 | 21 | 43 | 17 |
| D | 13 | 138 | 68 | 18 | 38 | 14 |
| E | 18 | 227 | 104 | 80 | 25 | 18 |
| F | 7 | 121 | 28 | 66 | 19 | 8 |
| G | 0 | 0 | 0 | 0 | 0 | 0 |

## Actor classes

| Value | Rules |
|---|---:|
| anonymous | 95 |
| authenticated-user | 526 |
| manufacturer | 228 |
| operator | 228 |
| checker | 6 |
| licensee-admin | 364 |
| platform-admin | 469 |
| restricted-read | 16 |
| pre-auth-runtime | 95 |
| worker | 6 |
| scheduled-job | 19 |
| migration | 0 |
| operator-admin | 1 |
| break-glass | 0 |

## Assurance levels

| Value | Rules |
|---|---:|
| none | 172 |
| password-verified | 799 |
| mfa-bootstrap | 5 |
| mfa-verified | 305 |
| step-up-verified | 25 |
| system-verified | 41 |
| operator-approved | 4 |
| dual-approved-break-glass | 0 |

## Commands

| Value | Rules |
|---|---:|
| SELECT | 797 |
| INSERT | 226 |
| UPDATE | 236 |
| DELETE | 92 |

## Boundary and deletion summary

Named-function rules: 956.
Restricted-worker rules: 25.
Approval-gated rules: 8.

| Hard-delete classification | Rules |
|---|---:|
| actor self-delete | 8 |
| not-applicable | 1259 |
| operator-approved | 1 |
| prohibited | 77 |
| retention delete | 1 |
| tenant-admin delete | 5 |

Lifecycle restrictions are carried per rule; Batch rules name the approved DRAFT through RELEASED transition states and terminal FAILED/VOIDED denials. Other state-bearing tables require their canonical service transition before a write can satisfy the rule.

