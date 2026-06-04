#!/usr/bin/env bash
set -euo pipefail

REGION="af-south-1"
ASG_NAME="mscqr-capetown-dr-asg"

aws autoscaling resume-processes \
  --region "$REGION" \
  --auto-scaling-group-name "$ASG_NAME"

aws autoscaling update-auto-scaling-group \
  --region "$REGION" \
  --auto-scaling-group-name "$ASG_NAME" \
  --min-size 2 \
  --desired-capacity 2 \
  --max-size 4
