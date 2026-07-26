# MSCQR full-database command semantics review

This is the compact human review of `command-semantics.json`. It defines architecture only: no SQL, grants, roles, RLS state, or runtime behavior are changed.

Rules: 1394; workflows mapped: 321/321.

## Review groups

| Group | Tables | Rules | SELECT | INSERT | UPDATE | DELETE |
|---|---:|---:|---:|---:|---:|---:|
| A | 23 | 462 | 301 | 34 | 96 | 31 |
| B | 3 | 210 | 195 | 6 | 4 | 5 |
| C | 15 | 235 | 155 | 21 | 42 | 17 |
| D | 13 | 141 | 70 | 19 | 38 | 14 |
| E | 18 | 226 | 103 | 80 | 25 | 18 |
| F | 7 | 120 | 28 | 65 | 19 | 8 |
| G | 0 | 0 | 0 | 0 | 0 | 0 |

## Actor classes

| Value | Rules |
|---|---:|
| anonymous | 91 |
| authenticated-user | 578 |
| manufacturer | 228 |
| operator | 223 |
| checker | 6 |
| licensee-admin | 348 |
| platform-admin | 453 |
| restricted-read | 16 |
| pre-auth-runtime | 91 |
| worker | 6 |
| scheduled-job | 21 |
| migration | 0 |
| operator-admin | 1 |
| break-glass | 0 |

## Assurance levels

| Value | Rules |
|---|---:|
| none | 168 |
| password-verified | 846 |
| mfa-bootstrap | 0 |
| mfa-verified | 308 |
| step-up-verified | 25 |
| system-verified | 43 |
| operator-approved | 4 |
| dual-approved-break-glass | 0 |

## Commands

| Value | Rules |
|---|---:|
| SELECT | 852 |
| INSERT | 225 |
| UPDATE | 224 |
| DELETE | 93 |

## Boundary and deletion summary

Named-function rules: 1047.
Restricted-worker rules: 27.
Approval-gated rules: 8.

| Hard-delete classification | Rules |
|---|---:|
| actor self-delete | 9 |
| not-applicable | 1301 |
| operator-approved | 1 |
| prohibited | 77 |
| retention delete | 1 |
| tenant-admin delete | 5 |

Lifecycle restrictions are carried per rule; Batch rules name the approved DRAFT through RELEASED transition states and terminal FAILED/VOIDED denials. Other state-bearing tables require their canonical service transition before a write can satisfy the rule.

