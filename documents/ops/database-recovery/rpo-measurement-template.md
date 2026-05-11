# RPO Measurement Template

Last updated: 2026-05-11

| Metric | Value |
| --- | --- |
| Target region |  |
| Latest usable backup time |  |
| Outage/freeze time |  |
| Restored DB available time |  |
| App connected time |  |
| Health passed time |  |
| Estimated data loss window |  |
| Final RPO |  |
| Target RPO |  |
| Pass/fail |  |

## Notes And Evidence Links

| Item | Link/Note |
| --- | --- |
| Backup/snapshot evidence |  |
| Restore evidence |  |
| App health evidence |  |
| Read-only smoke evidence |  |
| Write gate approval |  |
| Follow-up owner |  |

## Calculation Guidance

RPO is the difference between the latest usable recovery point and the outage or write-freeze time. If writes cannot be frozen, record that uncertainty as a risk and escalate before DNS cutover.
