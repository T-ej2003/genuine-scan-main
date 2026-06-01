# Cape Town Africa DNS Readiness

Last updated: 2026-06-01

## Current State

- Mumbai is current production for `www.mscqr.com`.
- Mumbai ASG health evidence and S3/default-credentials proof are complete.
- Cape Town ASG has reached healthy state after SSM parameter fixes and instance refresh.
- This pass is evidence cleanup and Africa DNS planning only. It must not mutate AWS, Route 53, secrets, MinIO, London, or Phase D automatic failover.

Cape Town values:

| Field | Value |
| --- | --- |
| Region | `af-south-1` |
| ASG | `mscqr-capetown-dr-asg` |
| Target group ARN | `arn:aws:elasticloadbalancing:af-south-1:368992683803:targetgroup/mscqr-capetown-frontend-tg/a9b43fd2d346e26d` |
| ALB DNS | `mscqr-capetown-alb-1730011881.af-south-1.elb.amazonaws.com` |
| ALB canonical hosted zone ID | `Z268VQBMOI5EKX` |

Mumbai default/global values for the Africa DNS plan:

| Field | Value |
| --- | --- |
| ALB DNS | `mscqr-mumbai-alb-1249752376.ap-south-1.elb.amazonaws.com` |
| ALB canonical hosted zone ID | `ZP97RAFLXTNZK` |

## Root Cause Of Previous Evidence Confusion

The previous Cape Town evidence attempt had two separate issues:

1. A shell newline handling bug caused two EC2 instance IDs to be passed as one malformed `--instance-ids` argument. Clean evidence must let the script discover ASG instance IDs, print them one per line, and pass them to AWS as separate shell arguments.
2. A raw ALB HTTPS check used the AWS `*.elb.amazonaws.com` hostname. That hostname is not covered by the MSCQR ACM certificate, so certificate hostname verification failure is expected and is not a Cape Town app failure.

DNS validation for regional routing must use real domain records or a real hostname covered by the certificate. Raw ALB DNS is valid for HTTP `/healthz` evidence only.

## Clean Cape Town Evidence Command

Run this from the repo root. It is read-only and writes logs under `/tmp/mscqr-asg-evidence/`.

```bash
cd /Users/abhiramteja/Downloads/genuine-scan-main
TARGET_REGION_GROUP=capetown \
AWS_REGION=af-south-1 \
ASG_NAME=mscqr-capetown-dr-asg \
TARGET_GROUP_ARN=arn:aws:elasticloadbalancing:af-south-1:368992683803:targetgroup/mscqr-capetown-frontend-tg/a9b43fd2d346e26d \
ALB_DNS_NAME=mscqr-capetown-alb-1730011881.af-south-1.elb.amazonaws.com \
ALB_HTTP_HEALTHZ_URL=http://mscqr-capetown-alb-1730011881.af-south-1.elb.amazonaws.com/healthz \
npm run ops:asg-health-evidence
```

If a certificate-valid DR hostname exists, add it as an optional real-hostname check:

```bash
DR_HOSTNAME=dr-capetown.mscqr.com \
DR_HOST_SCHEME=https \
DR_HEALTH_PATH=/healthz \
TARGET_REGION_GROUP=capetown \
AWS_REGION=af-south-1 \
ASG_NAME=mscqr-capetown-dr-asg \
TARGET_GROUP_ARN=arn:aws:elasticloadbalancing:af-south-1:368992683803:targetgroup/mscqr-capetown-frontend-tg/a9b43fd2d346e26d \
npm run ops:asg-health-evidence
```

Expected evidence contents:

- ASG state at start and final ASG state at end.
- Target health for the Cape Town target group.
- ASG instance IDs printed one per line.
- Instance profile and `MetadataOptions` for every ASG instance.
- `IMDS_METADATA_OPTIONS_CHECK=pass` for each instance, requiring `HttpTokens=required`, `HttpEndpoint=enabled`, and `HttpPutResponseHopLimit>=2`.
- Public `http://INSTANCE_PUBLIC_IP/healthz` result for each ASG node with a public IP.
- Raw Cape Town ALB `http://.../healthz` result over HTTP only.
- Safe object-storage readiness summary with no secret values.

## Africa DNS Plan-Only Command

This command generates a proposed Route 53 change batch and rollback batch only. It does not apply DNS.

```bash
cd /Users/abhiramteja/Downloads/genuine-scan-main
HOSTED_ZONE_ID=Z0569586VLFIGGVI7HAZ \
DOMAIN_NAME=mscqr.com \
WWW_DOMAIN_NAME=www.mscqr.com \
AFRICA_ALB_DNS_NAME=mscqr-capetown-alb-1730011881.af-south-1.elb.amazonaws.com \
AFRICA_ALB_HOSTED_ZONE_ID=Z268VQBMOI5EKX \
DEFAULT_ALB_DNS_NAME=mscqr-mumbai-alb-1249752376.ap-south-1.elb.amazonaws.com \
DEFAULT_ALB_HOSTED_ZONE_ID=ZP97RAFLXTNZK \
CURRENT_GLOBAL_ALB_DNS_NAME=mscqr-mumbai-alb-1249752376.ap-south-1.elb.amazonaws.com \
CURRENT_GLOBAL_ALB_HOSTED_ZONE_ID=ZP97RAFLXTNZK \
npm run ops:route53-africa-dns-plan
```

The generated cutover plan converts the apex from the current simple Mumbai ALB alias into:

- Default geolocation `*` alias to Mumbai.
- Africa geolocation `AF` alias to Cape Town.
- Existing `www.mscqr.com` CNAME-to-apex shape preserved unless `INCLUDE_WWW_CNAME=false` is explicitly set.

The rollback plan removes the geolocation records and restores the simple global Mumbai ALB alias.

## Guardrails

- Do not apply Route 53 changes from this pass.
- Do not replace production global/default Mumbai routing when adding Africa routing.
- Do not treat raw ALB HTTPS certificate mismatch as an app failure.
- Do not use raw ALB HTTPS as DNS validation.
- Do not print or copy secret values into evidence.
- Do not delete MinIO data or any AWS resource.
- Do not start London work or Phase D automatic failover in this pass.

## CTO Recommendations

- Before apply approval, export and review the current Route 53 record set for `mscqr.com` so the generated `DELETE` record exactly matches live state.
- Add a dedicated certificate-valid `dr-capetown.mscqr.com` validation record before Africa production routing; raw ALB HTTP is useful liveness evidence, not customer-grade DNS/TLS proof.
- Keep the Africa cutover as a small, reversible DNS change with an explicit rollback batch and a named incident commander approval.
- After Cape Town DNS evidence is complete, audit/rebuild London to the same ALB, ASG, IMDSv2, S3/default-credentials, and no-MinIO standard before Phase D automatic failover design resumes.
