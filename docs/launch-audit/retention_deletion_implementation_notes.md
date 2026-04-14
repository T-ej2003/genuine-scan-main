# Retention and Deletion Implementation Notes

This file records the engineering state of retention and deletion handling while final legal policy text is still under review.

## Confirmed implementation areas

- Operator authentication cookies and verification session cookies have explicit lifetime logic.
- Support issue submission can include diagnostics and screenshots.
- Incident and support evidence can be stored in object storage or upload paths.
- Customer verification guidance references 180-day logging expectations in existing docs.

## Engineering actions still required before final policy signoff

- confirm the final retention period for:
  - support tickets
  - support screenshots
  - incident evidence
  - audit logs
  - verification logs
- confirm the deletion path for:
  - closed support evidence
  - incident evidence after retention expiry
  - customer session or continuity artifacts no longer needed
- confirm whether any storage classes or lifecycle rules enforce those periods automatically in AWS

## Acceptance criteria

- named retention period exists for each data class
- named owner exists for deletion enforcement
- AWS or application jobs enforcing deletion are identified
- public legal wording matches actual engineering behavior
