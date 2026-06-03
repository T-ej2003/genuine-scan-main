#!/usr/bin/env bash
set -euo pipefail

REGION="eu-west-2"
ORIGINAL_B_NAT_ID="nat-0a51226e1f9190b2e"

aws ec2 replace-route \
  --region "$REGION" \
  --route-table-id rtb-08944319a1a049253 \
  --destination-cidr-block 0.0.0.0/0 \
  --nat-gateway-id "$ORIGINAL_B_NAT_ID"

aws ec2 replace-route \
  --region "$REGION" \
  --route-table-id rtb-0bd0293e2aca23c60 \
  --destination-cidr-block 0.0.0.0/0 \
  --nat-gateway-id "$ORIGINAL_B_NAT_ID"

aws ec2 describe-route-tables \
  --region "$REGION" \
  --route-table-ids rtb-08944319a1a049253 rtb-0bd0293e2aca23c60 \
  --query 'RouteTables[].{
    RouteTableId:RouteTableId,
    Name:Tags[?Key==`Name`]|[0].Value,
    DefaultRoutes:Routes[?DestinationCidrBlock==`0.0.0.0/0`].{NatGatewayId:NatGatewayId,State:State}
  }' \
  --output table
