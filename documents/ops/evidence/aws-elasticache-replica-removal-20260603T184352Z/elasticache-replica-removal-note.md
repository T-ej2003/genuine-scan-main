# AWS ElastiCache replica removal

## Change

Reduced London Valkey/Redis replication group from HA two-node posture to single-node posture.

## Replication group

`mscqr-redis-euw2-primary`

## Reason

14-day metrics showed very low utilization:
- CPU max around 3.3%.
- Memory usage below 1%.
- Zero evictions.
- Low connection count.
- ECS backend service currently has zero running tasks due image platform mismatch.

## Safety decision

Redis was not deleted because the ECS task definition still references `REDIS_URL`.

## Expected outcome

- Automatic failover disabled.
- Multi-AZ disabled.
- Replica count reduced to zero.
- One primary cache node remains.
