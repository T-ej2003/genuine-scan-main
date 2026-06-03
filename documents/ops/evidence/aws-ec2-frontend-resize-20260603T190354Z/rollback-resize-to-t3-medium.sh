#!/usr/bin/env bash
set -euo pipefail

REGION="eu-west-2"
INSTANCE_ID="i-024ec40bcbdb30035"
SOURCE_TYPE="t3.medium"
TARGET_GROUP_ARN="arn:aws:elasticloadbalancing:eu-west-2:368992683803:targetgroup/mscqr-frontend-tg-euw2/09ef3648e65481e6"
PUBLIC_URL="https://www.mscqr.com"

aws ec2 stop-instances \
  --region "$REGION" \
  --instance-ids "$INSTANCE_ID"

aws ec2 wait instance-stopped \
  --region "$REGION" \
  --instance-ids "$INSTANCE_ID"

aws ec2 modify-instance-attribute \
  --region "$REGION" \
  --instance-id "$INSTANCE_ID" \
  --instance-type "{\"Value\":\"$SOURCE_TYPE\"}"

aws ec2 start-instances \
  --region "$REGION" \
  --instance-ids "$INSTANCE_ID"

aws ec2 wait instance-running \
  --region "$REGION" \
  --instance-ids "$INSTANCE_ID"

sleep 90

aws elbv2 describe-target-health \
  --region "$REGION" \
  --target-group-arn "$TARGET_GROUP_ARN" \
  --output table

curl -I --max-time 20 "$PUBLIC_URL"
