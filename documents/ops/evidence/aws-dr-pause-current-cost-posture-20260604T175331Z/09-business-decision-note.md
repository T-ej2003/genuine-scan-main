# DR pause business decision note

Mumbai and Cape Town ASG-managed compute is paused. ASG desired capacity is zero and Launch is suspended.

Remaining active/cost-bearing DR components may include:
- ALB
- Target groups
- RDS metadata/storage/snapshots, depending on DB state
- ElastiCache
- EBS volumes
- ENIs
- logs/metrics

Recommended pause posture until July second week:
- Keep ALBs unless cold-DR teardown is explicitly approved.
- Keep ElastiCache unless cold-DR Redis recreation is explicitly approved.
- Monitor RDS stopped state because AWS can restart stopped RDS after the stop window.
- Re-enable ASGs using generated resume scripts only after data/application re-sync.
