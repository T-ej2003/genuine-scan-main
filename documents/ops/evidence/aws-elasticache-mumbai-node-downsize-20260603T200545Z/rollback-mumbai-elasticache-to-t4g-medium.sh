#!/usr/bin/env bash
set -euo pipefail

REGION="ap-south-1"
RG_ID="mscqr-redis-aps1-primary"
ROLLBACK_NODE_TYPE="cache.t4g.medium"

aws elasticache modify-replication-group \
  --region "$REGION" \
  --replication-group-id "$RG_ID" \
  --cache-node-type "$ROLLBACK_NODE_TYPE" \
  --apply-immediately
