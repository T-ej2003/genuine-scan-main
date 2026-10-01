# Broker replay transaction permission correction

Production state serial 111 remains authoritative. No historical plan may be replayed.

Both inventory recovery paths invoke DynamoDB TransactWriteItems. Normal recovery uses Update, Put and ConditionCheck; absent-predecessor recovery uses Put and ConditionCheck. The existing broker statement already permits all required operations except ConditionCheckItem.

The correction adds only dynamodb:ConditionCheckItem to ClaimOnlyStageBReplayRows, retaining aws_dynamodb_table.replay.arn. It adds no role, policy, table, wildcard resource or recovery behavior.

After merge, reconcile this exact policy through the governed current-source authorization/apply path. Verify live IAM simulation, reauthenticate absence of predecessor/successor and successful inventory/rotation state, then permit one atomic successor. Do not retry after a durable reservation without authenticating the outcome.

Recommendation: retain the action-to-transaction regression so future recovery changes cannot silently omit exact-table IAM authority. Broader hardening remains post-deployment work.
