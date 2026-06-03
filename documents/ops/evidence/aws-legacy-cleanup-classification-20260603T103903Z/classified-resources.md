# MSCQR AWS Legacy Cleanup Inventory Classification

Source inventory path/archive: `/Users/abhiramteja/Downloads/genuine-scan-main/artifacts/aws-cleanup-inventory/20260603T103903Z.tar.gz`
Generated timestamp: `2026-06-03T11:05:22.906Z`

**Warning: no deletion, stop, detach, Route 53 change, IAM change, or AWS mutation was performed. This report is classification and operator review only.**

## Summary Counts

- Total resources classified: 153
- KEEP: 130
- REVIEW_REQUIRED: 16
- SAFE_TO_STOP: 0
- SAFE_TO_DELETE_LATER: 0
- NEVER_DELETE_WITHOUT_BACKUP: 7

## Current Production KEEP Resources

- **KEEP** route53/global/hosted-zone: `Z0569586VLFIGGVI7HAZ` (mscqr.com.) - Active production DNS zone.
- **KEEP** route53/global/record: `mscqr.com. A africa-capetown` (mscqr.com.) - Current production DNS policy.
- **KEEP** route53/global/record: `mscqr.com. A default-mumbai` (mscqr.com.) - Current production DNS policy.
- **KEEP** route53/global/record: `mscqr.com. A europe-london` (mscqr.com.) - Current production DNS policy.
- **KEEP** route53/global/record: `mscqr.com. MX` (mscqr.com.) - DMARC/DKIM/SPF/MX/NS/SOA/TXT records are not cleanup candidates.
- **KEEP** route53/global/record: `mscqr.com. NS` (mscqr.com.) - DMARC/DKIM/SPF/MX/NS/SOA/TXT records are not cleanup candidates.
- **KEEP** route53/global/record: `mscqr.com. SOA` (mscqr.com.) - DMARC/DKIM/SPF/MX/NS/SOA/TXT records are not cleanup candidates.
- **KEEP** route53/global/record: `mscqr.com. TXT` (mscqr.com.) - DMARC/DKIM/SPF/MX/NS/SOA/TXT records are not cleanup candidates.
- **KEEP** route53/global/record: `_2e0f2fe7ab15a9da737609c8ae0cb738.mscqr.com. CNAME` (_2e0f2fe7ab15a9da737609c8ae0cb738.mscqr.com.) - Preserve certificate validation while certs are active.
- **KEEP** route53/global/record: `_dmarc.mscqr.com. TXT` (_dmarc.mscqr.com.) - DMARC/DKIM/SPF/MX/NS/SOA/TXT records are not cleanup candidates.
- **KEEP** route53/global/record: `default._domainkey.mscqr.com. TXT` (default._domainkey.mscqr.com.) - DMARC/DKIM/SPF/MX/NS/SOA/TXT records are not cleanup candidates.
- **KEEP** route53/global/record: `www.mscqr.com. CNAME` (www.mscqr.com.) - Preserve public web hostname record.
- **KEEP** s3/global/bucket: `mscqr-alb-logs-afs1-368992683803` - Keep or review retention separately; do not delete in this pass.
- **KEEP** s3/global/bucket: `mscqr-alb-logs-aps1-368992683803` - Keep or review retention separately; do not delete in this pass.
- **KEEP** s3/global/bucket: `mscqr-prod-afs1-artifacts-368992683803-af-south-1` - Production object storage uses S3 default credentials.
- **KEEP** s3/global/bucket: `mscqr-prod-aps1-artifacts-368992683803-ap-south-1` - Production object storage uses S3 default credentials.
- **KEEP** s3/global/bucket: `mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an` - Production object storage uses S3 default credentials.
- **KEEP** iam/global/role: `github-actions-mscqr-deploy` - Current production/GitHub operational role.
- **KEEP** iam/global/role: `mscqr-asg-web-role-aps1` - Current production/GitHub operational role.
- **KEEP** iam/global/role: `mscqr-ec2-s3-artifacts-role` - Current production/GitHub operational role.
- **KEEP** iam/global/role: `mscqr-ec2-s3-artifacts-role-afs1` - Current production/GitHub operational role.
- **KEEP** iam/global/role: `mscqr-ec2-s3-artifacts-role-aps1` - Current production/GitHub operational role.
- **KEEP** iam/global/role: `mscqr-github-auto-failover-readonly` - Current production/GitHub operational role.
- **KEEP** iam/global/policy: `mscqr-ec2-s3-artifacts-policy-aps1` - Current regional production object-storage access policy.
- **KEEP** iam/global/policy: `mscqr-ec2-s3-artifacts-policy-afs1` - Current regional production object-storage access policy.
- **KEEP** ec2/ap-south-1/instance: `i-01a75d3af870584c7` - Running production or operational instance.
- **KEEP** ec2/ap-south-1/instance: `i-04ae3b689ab72a68a` (mscqr-prod-mumbai) - Running production or operational instance.
- **KEEP** ec2/ap-south-1/instance: `i-0278c3cd414aa7d29` - Running production or operational instance.
- **KEEP** ebs/ap-south-1/volume: `vol-0565b1380fd5b95af` - Attached volumes are protected.
- **KEEP** ebs/ap-south-1/volume: `vol-0470fcba474e66369` - Attached volumes are protected.
- **KEEP** ebs/ap-south-1/volume: `vol-0df4e7d2594aa7ef3` - Attached volumes are protected.
- **KEEP** ec2/ap-south-1/elastic-ip: `eipalloc-0cda0cfe1df1a8322` (13.207.106.241) - Associated EIP is protected.
- **KEEP** ec2/ap-south-1/elastic-ip: `eipalloc-09b30cdf6c251f1ad` (13.207.98.190) - Associated EIP is protected.
- **KEEP** ec2/ap-south-1/elastic-ip: `eipalloc-0edf6fdd3b389d52e` (15.206.45.108) - Associated EIP is protected.
- **KEEP** elbv2/ap-south-1/load-balancer: `arn:aws:elasticloadbalancing:ap-south-1:368992683803:loadbalancer/app/mscqr-mumbai-alb/025ad0cb77546ee0` (mscqr-mumbai-alb) - Current DNS policy target.
- **KEEP** elbv2/ap-south-1/target-group: `arn:aws:elasticloadbalancing:ap-south-1:368992683803:targetgroup/mscqr-mumbai-frontend-tg/68982ccd4d8c26c1` (mscqr-mumbai-frontend-tg) - Current production routing dependency.
- **KEEP** autoscaling/ap-south-1/auto-scaling-group: `mscqr-mumbai-dr-asg` - Current regional DR/prod capacity.
- **KEEP** launch-template/ap-south-1/launch-template: `lt-02570cc00f696ee4c` (mscqr-mumbai-dr-lt) - Current ASG launch template.
- **KEEP** security-group/ap-south-1/security-group: `sg-0771ea7e59f7a49d4` (mscqr-ec2-web-sg-aps1) - Attached security groups are protected.
- **KEEP** security-group/ap-south-1/security-group: `sg-0ce45eda9cd11aa80` (mscqr-rds-sg-aps1) - Attached security groups are protected.
- **KEEP** security-group/ap-south-1/security-group: `sg-0924027a22e96be48` (mscqr-mumbai-alb-sg) - Attached security groups are protected.
- **KEEP** security-group/ap-south-1/security-group: `sg-05a60dd45bc09e637` (mscqr-redis-sg-aps1) - Attached security groups are protected.
- **KEEP** network-interface/ap-south-1/network-interface: `eni-06fff34694b568940` - Attached ENI is protected.
- **KEEP** network-interface/ap-south-1/network-interface: `eni-094f3f5cf0ab1fa8e` (ELB app/mscqr-mumbai-alb/025ad0cb77546ee0) - Attached ENI is protected.
- **KEEP** network-interface/ap-south-1/network-interface: `eni-0e7ca9fd62b446766` (ElastiCache mscqr-redis-aps1-primary-002) - Attached ENI is protected.
- **KEEP** network-interface/ap-south-1/network-interface: `eni-0b0c78c72654108b0` (ELB app/mscqr-mumbai-alb/025ad0cb77546ee0) - Attached ENI is protected.
- **KEEP** network-interface/ap-south-1/network-interface: `eni-01bcb43b1608b173e` - Attached ENI is protected.
- **KEEP** network-interface/ap-south-1/network-interface: `eni-0b6e91ad3c22886d2` (RDSNetworkInterface) - Attached ENI is protected.
- **KEEP** network-interface/ap-south-1/network-interface: `eni-0e8ea92f98fe0cd2f` (ElastiCache mscqr-redis-aps1-primary-001) - Attached ENI is protected.
- **KEEP** network-interface/ap-south-1/network-interface: `eni-02c00fca9c1e649e0` - Attached ENI is protected.
- **KEEP** acm/ap-south-1/certificate: `arn:aws:acm:ap-south-1:368992683803:certificate/ac1be953-fdad-473e-8500-efbd02cb3715` (mscqr.com) - Certificate attached to active infrastructure.
- **KEEP** cloudwatch/ap-south-1/alarm: `MSCQR-mumbai-ALB-5XX` - Current operational alarm candidate.
- **KEEP** cloudwatch/ap-south-1/alarm: `MSCQR-mumbai-EC2-CPU-70` - Current operational alarm candidate.
- **KEEP** cloudwatch/ap-south-1/alarm: `MSCQR-mumbai-Target-5XX` - Current operational alarm candidate.
- **KEEP** cloudwatch/ap-south-1/alarm: `MSCQR-mumbai-TargetResponseTime-p95` - Current operational alarm candidate.
- **KEEP** cloudwatch/ap-south-1/alarm: `MSCQR-mumbai-UnhealthyHosts` - Current operational alarm candidate.
- **KEEP** cloudwatch/ap-south-1/alarm: `mscqr-mumbai-ec2-cpu-high` - Current operational alarm candidate.
- **KEEP** cloudwatch/ap-south-1/alarm: `mscqr-mumbai-ec2-status-check-failed` - Current operational alarm candidate.
- **KEEP** cloudwatch/ap-south-1/alarm: `mscqr-mumbai-rds-cpu-high` - Current operational alarm candidate.
- **KEEP** cloudwatch/ap-south-1/alarm: `mscqr-mumbai-rds-db-connections-high` - Current operational alarm candidate.
- **KEEP** cloudwatch/ap-south-1/alarm: `mscqr-mumbai-rds-free-storage-low` - Current operational alarm candidate.
- **KEEP** ec2/af-south-1/instance: `i-01b1f9da435ed2f99` - Running production or operational instance.
- **KEEP** ec2/af-south-1/instance: `i-064223a25caf64770` (mscqr-prod-capetown) - Running production or operational instance.
- **KEEP** ec2/af-south-1/instance: `i-0ec7b53df203291ff` - Running production or operational instance.
- **KEEP** ebs/af-south-1/volume: `vol-01c1a3af78626c883` - Attached volumes are protected.
- **KEEP** ebs/af-south-1/volume: `vol-03ecace0015529ecf` - Attached volumes are protected.
- **KEEP** ebs/af-south-1/volume: `vol-069f748509579be8f` - Attached volumes are protected.
- **KEEP** ec2/af-south-1/elastic-ip: `eipalloc-0966c373ad1b03e69` (13.247.109.230) - Associated EIP is protected.
- **KEEP** ec2/af-south-1/elastic-ip: `eipalloc-0e1efff274edfe8d7` (13.247.165.129) - Associated EIP is protected.
- **KEEP** ec2/af-south-1/elastic-ip: `eipalloc-01e38750bd4be698f` (15.240.28.113) - Associated EIP is protected.
- **KEEP** elbv2/af-south-1/load-balancer: `arn:aws:elasticloadbalancing:af-south-1:368992683803:loadbalancer/app/mscqr-capetown-alb/b7defd5707ad181c` (mscqr-capetown-alb) - Current DNS policy target.
- **KEEP** elbv2/af-south-1/target-group: `arn:aws:elasticloadbalancing:af-south-1:368992683803:targetgroup/mscqr-capetown-frontend-tg/a9b43fd2d346e26d` (mscqr-capetown-frontend-tg) - Current production routing dependency.
- **KEEP** autoscaling/af-south-1/auto-scaling-group: `mscqr-capetown-dr-asg` - Current regional DR/prod capacity.
- **KEEP** launch-template/af-south-1/launch-template: `lt-04eeeecdf7ff884fe` (mscqr-capetown-dr-lt) - Current ASG launch template.
- **KEEP** security-group/af-south-1/security-group: `sg-0f768d6fc564123b1` (mscqr-rds-sg-afs1) - Attached security groups are protected.
- **KEEP** security-group/af-south-1/security-group: `sg-061c4ffc734e1d149` (mscqr-redis-sg-afs1) - Attached security groups are protected.
- **KEEP** security-group/af-south-1/security-group: `sg-0ad358fd72d15bd3f` (mscqr-capetown-alb-sg) - Attached security groups are protected.
- **KEEP** security-group/af-south-1/security-group: `sg-0d8f560e4f6452aa5` (mscqr-ec2-web-sg-afs1) - Attached security groups are protected.
- **KEEP** network-interface/af-south-1/network-interface: `eni-0f44c7a9f12a7173a` (ELB app/mscqr-capetown-alb/b7defd5707ad181c) - Attached ENI is protected.
- **KEEP** network-interface/af-south-1/network-interface: `eni-06f2da01d828ec730` - Attached ENI is protected.
- **KEEP** network-interface/af-south-1/network-interface: `eni-03315255108a10d77` (ElastiCache mscqr-redis-afs1-primary-001) - Attached ENI is protected.
- **KEEP** network-interface/af-south-1/network-interface: `eni-00a2c0cfe854768c5` (RDSNetworkInterface) - Attached ENI is protected.
- **KEEP** network-interface/af-south-1/network-interface: `eni-059f35b271ff4ed7c` (ElastiCache mscqr-redis-afs1-primary-002) - Attached ENI is protected.
- **KEEP** network-interface/af-south-1/network-interface: `eni-06d9d12a42b3e1054` (ELB app/mscqr-capetown-alb/b7defd5707ad181c) - Attached ENI is protected.
- **KEEP** network-interface/af-south-1/network-interface: `eni-0f834b8389774d57e` - Attached ENI is protected.
- **KEEP** network-interface/af-south-1/network-interface: `eni-0afad4f6297c8dd80` - Attached ENI is protected.
- **KEEP** acm/af-south-1/certificate: `arn:aws:acm:af-south-1:368992683803:certificate/989885f0-4a26-4995-8b83-30be93ab2cfc` (mscqr.com) - Certificate attached to active infrastructure.
- **KEEP** cloudwatch/af-south-1/alarm: `MSCQR-capetown-ALB-5XX` - Current operational alarm candidate.
- **KEEP** cloudwatch/af-south-1/alarm: `MSCQR-capetown-EC2-CPU-70` - Current operational alarm candidate.
- **KEEP** cloudwatch/af-south-1/alarm: `MSCQR-capetown-Target-5XX` - Current operational alarm candidate.
- **KEEP** cloudwatch/af-south-1/alarm: `MSCQR-capetown-TargetResponseTime-p95` - Current operational alarm candidate.
- **KEEP** cloudwatch/af-south-1/alarm: `MSCQR-capetown-UnhealthyHosts` - Current operational alarm candidate.
- **KEEP** cloudwatch/af-south-1/alarm: `mscqr-capetown-ec2-cpu-high` - Current operational alarm candidate.
- **KEEP** cloudwatch/af-south-1/alarm: `mscqr-capetown-ec2-status-check-failed` - Current operational alarm candidate.
- **KEEP** cloudwatch/af-south-1/alarm: `mscqr-capetown-rds-cpu-high` - Current operational alarm candidate.
- **KEEP** cloudwatch/af-south-1/alarm: `mscqr-capetown-rds-db-connections-high` - Current operational alarm candidate.
- **KEEP** cloudwatch/af-south-1/alarm: `mscqr-capetown-rds-free-storage-low` - Current operational alarm candidate.
- **KEEP** ec2/eu-west-2/instance: `i-024ec40bcbdb30035` (mscqr-prod_london) - Running production or operational instance.
- **KEEP** ec2/eu-west-2/instance: `i-0628b4a4a06f6e4d3` (mscqr-github-actions-runner) - Running production or operational instance.
- **KEEP** ebs/eu-west-2/volume: `vol-05b02fe2ee329505f` - Attached volumes are protected.
- **KEEP** ebs/eu-west-2/volume: `vol-05cc68f5d86b0ccc6` - Attached volumes are protected.
- **KEEP** ec2/eu-west-2/elastic-ip: `eipalloc-0e355030bdb47ec4d` (13.135.108.69) - Associated EIP is protected.
- **KEEP** ec2/eu-west-2/elastic-ip: `eipalloc-0e1f6867d5a411bb1` (16.61.0.97) - Associated EIP is protected.
- **KEEP** ec2/eu-west-2/elastic-ip: `eipalloc-00779949767f21cfa` (18.133.208.221) - Associated EIP is protected.
- **KEEP** ec2/eu-west-2/elastic-ip: `eipalloc-056bbb4cf49779295` (18.135.158.1) - Associated EIP is protected.
- **KEEP** ec2/eu-west-2/elastic-ip: `eipalloc-0d048b9168225c496` (3.9.15.121) - Associated EIP is protected.
- **KEEP** ec2/eu-west-2/elastic-ip: `eipalloc-0d5bae537b16aece4` (35.179.203.86) - Associated EIP is protected.
- **KEEP** elbv2/eu-west-2/load-balancer: `arn:aws:elasticloadbalancing:eu-west-2:368992683803:loadbalancer/app/mscqr-alb-euw2/cda0292be6e39608` (mscqr-alb-euw2) - Current DNS policy target.
- **KEEP** elbv2/eu-west-2/target-group: `arn:aws:elasticloadbalancing:eu-west-2:368992683803:targetgroup/mscqr-frontend-tg-euw2/09ef3648e65481e6` (mscqr-frontend-tg-euw2) - Current production routing dependency.
- **KEEP** security-group/eu-west-2/security-group: `sg-017d8b3b4be470165` (ec2-rds-1) - Attached security groups are protected.
- **KEEP** security-group/eu-west-2/security-group: `sg-0a7cbddd9770b220d` (mscqr-alb-sg-euw2) - Attached security groups are protected.
- **KEEP** security-group/eu-west-2/security-group: `sg-0e669ac5a54fdca9d` (mscqr-ec2-web-sg-euw2) - Attached security groups are protected.
- **KEEP** security-group/eu-west-2/security-group: `sg-05128bf9006ff6ea9` (mscqr-github-runner-sg-euw2) - Attached security groups are protected.
- **KEEP** security-group/eu-west-2/security-group: `sg-0db971332ae625441` (mscqr-ecs-sg-euw2) - Attached security groups are protected.
- **KEEP** security-group/eu-west-2/security-group: `sg-07db1a9130c6df8d5` (rds-ec2-1) - Attached security groups are protected.
- **KEEP** network-interface/eu-west-2/network-interface: `eni-076c3556f9a8097f2` (ElastiCache mscqr-redis-euw2-primary-001) - Attached ENI is protected.
- **KEEP** network-interface/eu-west-2/network-interface: `eni-0f7e94c94c71d04ba` (ELB app/mscqr-alb-euw2/cda0292be6e39608) - Attached ENI is protected.
- **KEEP** network-interface/eu-west-2/network-interface: `eni-04093255d4b517221` (Interface for NAT Gateway nat-0a51226e1f9190b2e) - Attached ENI is protected.
- **KEEP** network-interface/eu-west-2/network-interface: `eni-006057d805dacec95` - Attached ENI is protected.
- **KEEP** network-interface/eu-west-2/network-interface: `eni-0a5cd8d8da0c87d0a` (ELB app/mscqr-alb-euw2/cda0292be6e39608) - Attached ENI is protected.
- **KEEP** network-interface/eu-west-2/network-interface: `eni-0e08a5968473dfc3f` (ElastiCache mscqr-redis-euw2-primary-002) - Attached ENI is protected.
- **KEEP** network-interface/eu-west-2/network-interface: `eni-04f64b96fad9969ce` - Attached ENI is protected.
- **KEEP** network-interface/eu-west-2/network-interface: `eni-0f10f3b7d7d976e14` (RDSNetworkInterface) - Attached ENI is protected.
- **KEEP** network-interface/eu-west-2/network-interface: `eni-0bcec4c899f2fa5bc` (Interface for NAT Gateway nat-0be609dfc6ce97dc3) - Attached ENI is protected.
- **KEEP** acm/eu-west-2/certificate: `arn:aws:acm:eu-west-2:368992683803:certificate/297215d5-aebb-4c76-8323-564c147b0271` (mscqr.com) - Certificate attached to active infrastructure.
- **KEEP** cloudwatch/eu-west-2/alarm: `mscqr-ec2-cpu-high` - Current operational alarm candidate.
- **KEEP** cloudwatch/eu-west-2/alarm: `mscqr-ec2-status-check-failed` - Current operational alarm candidate.
- **KEEP** cloudwatch/eu-west-2/alarm: `mscqr-rds-cpu-high` - Current operational alarm candidate.
- **KEEP** cloudwatch/eu-west-2/alarm: `mscqr-rds-db-connections-high` - Current operational alarm candidate.
- **KEEP** cloudwatch/eu-west-2/alarm: `mscqr-rds-free-storage-low` - Current operational alarm candidate.

## REVIEW_REQUIRED Resources

- **REVIEW_REQUIRED** route53/global/record: `dr-capetown.mscqr.com. A` (dr-capetown.mscqr.com.) - Hard rule: DR test records are REVIEW_REQUIRED unless docs prove active use.
- **REVIEW_REQUIRED** route53/global/record: `dr-mumbai.mscqr.com. A` (dr-mumbai.mscqr.com.) - Hard rule: DR test records are REVIEW_REQUIRED unless docs prove active use.
- **REVIEW_REQUIRED** route53/global/record: `_b038cd46106cbc0a3d8683da0d9481d8.www.mscqr.com. CNAME` (_b038cd46106cbc0a3d8683da0d9481d8.www.mscqr.com.) - DNS record is ambiguous; review before any future action.
- **REVIEW_REQUIRED** iam/global/role: `mscqr-ecs-execution-role` - Review trust policy, attachments, and last-used data before any future action.
- **REVIEW_REQUIRED** iam/global/role: `mscqr-ecs-task-role` - Review trust policy, attachments, and last-used data before any future action.
- **REVIEW_REQUIRED** security-group/ap-south-1/security-group: `sg-080278ac70122fce1` (default) - Security group requires ENI/reference console review.
- **REVIEW_REQUIRED** security-group/af-south-1/security-group: `sg-0d6af4df627e3fe43` (default) - Security group requires ENI/reference console review.
- **REVIEW_REQUIRED** elbv2/eu-west-2/target-group: `arn:aws:elasticloadbalancing:eu-west-2:368992683803:targetgroup/mscqr-backend-tg-euw2/6e970e6a19a28d75` (mscqr-backend-tg-euw2) - Target group needs listener/ASG/target-health review.
- **REVIEW_REQUIRED** security-group/eu-west-2/security-group: `sg-099af13ddef6abf9c` (rds_sg_mscqr_euw2) - Security group requires ENI/reference console review.
- **REVIEW_REQUIRED** security-group/eu-west-2/security-group: `sg-0cf8506e2e846ef51` (launch-wizard-1) - Security group requires ENI/reference console review.
- **REVIEW_REQUIRED** security-group/eu-west-2/security-group: `sg-0f70603411e227960` (default) - Security group requires ENI/reference console review.
- **REVIEW_REQUIRED** ecs/eu-west-2/cluster: `arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main` (mscqr-prod-euw2-main) - Review whether ECS release workflows still use this resource.
- **REVIEW_REQUIRED** ecr/eu-west-2/repository: `mscqr-backend` - Do not remove images/repos without release history review.
- **REVIEW_REQUIRED** ecr/eu-west-2/repository: `mscqr-worker` - Do not remove images/repos without release history review.
- **REVIEW_REQUIRED** ecr/eu-west-2/repository: `mscqr-web` - Do not remove images/repos without release history review.
- **REVIEW_REQUIRED** security-group/us-east-1/security-group: `sg-03a7f996516587951` (default) - Security group requires ENI/reference console review.

## SAFE_TO_STOP Candidates

- None.

## SAFE_TO_DELETE_LATER Candidates

- None.

## NEVER_DELETE_WITHOUT_BACKUP Resources

- **NEVER_DELETE_WITHOUT_BACKUP** rds/ap-south-1/db-instance: `mscqr-prod-db-aps1` - Never delete without backup/export/snapshot and explicit approval.
- **NEVER_DELETE_WITHOUT_BACKUP** rds/ap-south-1/manual-snapshot: `mscqr-prod-db-aps1-manual-2026-04-27` - Never delete without retention review and explicit approval.
- **NEVER_DELETE_WITHOUT_BACKUP** rds/af-south-1/db-instance: `mscqr-prod-db-afs1` - Never delete without backup/export/snapshot and explicit approval.
- **NEVER_DELETE_WITHOUT_BACKUP** rds/af-south-1/manual-snapshot: `mscqr-dr-capetown-restore-test-20260512-snapshot` - Never delete without retention review and explicit approval.
- **NEVER_DELETE_WITHOUT_BACKUP** rds/eu-west-2/db-instance: `mscqr-prod-db` - Never delete without backup/export/snapshot and explicit approval.
- **NEVER_DELETE_WITHOUT_BACKUP** rds/eu-west-2/manual-snapshot: `mscqr-dr-restore-test-20260511-snapshot` - Never delete without retention review and explicit approval.
- **NEVER_DELETE_WITHOUT_BACKUP** rds/eu-west-2/manual-snapshot: `mscqr-prod-db-post-deploy-2026-04-27` - Never delete without retention review and explicit approval.

## Per-Service Review Sections

### route53

- **KEEP** route53/global/hosted-zone: `Z0569586VLFIGGVI7HAZ` (mscqr.com.) - Active production DNS zone.
- **KEEP** route53/global/record: `mscqr.com. A africa-capetown` (mscqr.com.) - Current production DNS policy.
- **KEEP** route53/global/record: `mscqr.com. A default-mumbai` (mscqr.com.) - Current production DNS policy.
- **KEEP** route53/global/record: `mscqr.com. A europe-london` (mscqr.com.) - Current production DNS policy.
- **KEEP** route53/global/record: `mscqr.com. MX` (mscqr.com.) - DMARC/DKIM/SPF/MX/NS/SOA/TXT records are not cleanup candidates.
- **KEEP** route53/global/record: `mscqr.com. NS` (mscqr.com.) - DMARC/DKIM/SPF/MX/NS/SOA/TXT records are not cleanup candidates.
- **KEEP** route53/global/record: `mscqr.com. SOA` (mscqr.com.) - DMARC/DKIM/SPF/MX/NS/SOA/TXT records are not cleanup candidates.
- **KEEP** route53/global/record: `mscqr.com. TXT` (mscqr.com.) - DMARC/DKIM/SPF/MX/NS/SOA/TXT records are not cleanup candidates.
- **KEEP** route53/global/record: `_2e0f2fe7ab15a9da737609c8ae0cb738.mscqr.com. CNAME` (_2e0f2fe7ab15a9da737609c8ae0cb738.mscqr.com.) - Preserve certificate validation while certs are active.
- **KEEP** route53/global/record: `_dmarc.mscqr.com. TXT` (_dmarc.mscqr.com.) - DMARC/DKIM/SPF/MX/NS/SOA/TXT records are not cleanup candidates.
- **KEEP** route53/global/record: `default._domainkey.mscqr.com. TXT` (default._domainkey.mscqr.com.) - DMARC/DKIM/SPF/MX/NS/SOA/TXT records are not cleanup candidates.
- **REVIEW_REQUIRED** route53/global/record: `dr-capetown.mscqr.com. A` (dr-capetown.mscqr.com.) - Hard rule: DR test records are REVIEW_REQUIRED unless docs prove active use.
- **REVIEW_REQUIRED** route53/global/record: `dr-mumbai.mscqr.com. A` (dr-mumbai.mscqr.com.) - Hard rule: DR test records are REVIEW_REQUIRED unless docs prove active use.
- **KEEP** route53/global/record: `www.mscqr.com. CNAME` (www.mscqr.com.) - Preserve public web hostname record.
- **REVIEW_REQUIRED** route53/global/record: `_b038cd46106cbc0a3d8683da0d9481d8.www.mscqr.com. CNAME` (_b038cd46106cbc0a3d8683da0d9481d8.www.mscqr.com.) - DNS record is ambiguous; review before any future action.

### s3

- **KEEP** s3/global/bucket: `mscqr-alb-logs-afs1-368992683803` - Keep or review retention separately; do not delete in this pass.
- **KEEP** s3/global/bucket: `mscqr-alb-logs-aps1-368992683803` - Keep or review retention separately; do not delete in this pass.
- **KEEP** s3/global/bucket: `mscqr-prod-afs1-artifacts-368992683803-af-south-1` - Production object storage uses S3 default credentials.
- **KEEP** s3/global/bucket: `mscqr-prod-aps1-artifacts-368992683803-ap-south-1` - Production object storage uses S3 default credentials.
- **KEEP** s3/global/bucket: `mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an` - Production object storage uses S3 default credentials.

### iam

- **KEEP** iam/global/role: `github-actions-mscqr-deploy` - Current production/GitHub operational role.
- **KEEP** iam/global/role: `mscqr-asg-web-role-aps1` - Current production/GitHub operational role.
- **KEEP** iam/global/role: `mscqr-ec2-s3-artifacts-role` - Current production/GitHub operational role.
- **KEEP** iam/global/role: `mscqr-ec2-s3-artifacts-role-afs1` - Current production/GitHub operational role.
- **KEEP** iam/global/role: `mscqr-ec2-s3-artifacts-role-aps1` - Current production/GitHub operational role.
- **REVIEW_REQUIRED** iam/global/role: `mscqr-ecs-execution-role` - Review trust policy, attachments, and last-used data before any future action.
- **REVIEW_REQUIRED** iam/global/role: `mscqr-ecs-task-role` - Review trust policy, attachments, and last-used data before any future action.
- **KEEP** iam/global/role: `mscqr-github-auto-failover-readonly` - Current production/GitHub operational role.
- **KEEP** iam/global/policy: `mscqr-ec2-s3-artifacts-policy-aps1` - Current regional production object-storage access policy.
- **KEEP** iam/global/policy: `mscqr-ec2-s3-artifacts-policy-afs1` - Current regional production object-storage access policy.

### ec2

- **KEEP** ec2/ap-south-1/instance: `i-01a75d3af870584c7` - Running production or operational instance.
- **KEEP** ec2/ap-south-1/instance: `i-04ae3b689ab72a68a` (mscqr-prod-mumbai) - Running production or operational instance.
- **KEEP** ec2/ap-south-1/instance: `i-0278c3cd414aa7d29` - Running production or operational instance.
- **KEEP** ec2/ap-south-1/elastic-ip: `eipalloc-0cda0cfe1df1a8322` (13.207.106.241) - Associated EIP is protected.
- **KEEP** ec2/ap-south-1/elastic-ip: `eipalloc-09b30cdf6c251f1ad` (13.207.98.190) - Associated EIP is protected.
- **KEEP** ec2/ap-south-1/elastic-ip: `eipalloc-0edf6fdd3b389d52e` (15.206.45.108) - Associated EIP is protected.
- **KEEP** ec2/af-south-1/instance: `i-01b1f9da435ed2f99` - Running production or operational instance.
- **KEEP** ec2/af-south-1/instance: `i-064223a25caf64770` (mscqr-prod-capetown) - Running production or operational instance.
- **KEEP** ec2/af-south-1/instance: `i-0ec7b53df203291ff` - Running production or operational instance.
- **KEEP** ec2/af-south-1/elastic-ip: `eipalloc-0966c373ad1b03e69` (13.247.109.230) - Associated EIP is protected.
- **KEEP** ec2/af-south-1/elastic-ip: `eipalloc-0e1efff274edfe8d7` (13.247.165.129) - Associated EIP is protected.
- **KEEP** ec2/af-south-1/elastic-ip: `eipalloc-01e38750bd4be698f` (15.240.28.113) - Associated EIP is protected.
- **KEEP** ec2/eu-west-2/instance: `i-024ec40bcbdb30035` (mscqr-prod_london) - Running production or operational instance.
- **KEEP** ec2/eu-west-2/instance: `i-0628b4a4a06f6e4d3` (mscqr-github-actions-runner) - Running production or operational instance.
- **KEEP** ec2/eu-west-2/elastic-ip: `eipalloc-0e355030bdb47ec4d` (13.135.108.69) - Associated EIP is protected.
- **KEEP** ec2/eu-west-2/elastic-ip: `eipalloc-0e1f6867d5a411bb1` (16.61.0.97) - Associated EIP is protected.
- **KEEP** ec2/eu-west-2/elastic-ip: `eipalloc-00779949767f21cfa` (18.133.208.221) - Associated EIP is protected.
- **KEEP** ec2/eu-west-2/elastic-ip: `eipalloc-056bbb4cf49779295` (18.135.158.1) - Associated EIP is protected.
- **KEEP** ec2/eu-west-2/elastic-ip: `eipalloc-0d048b9168225c496` (3.9.15.121) - Associated EIP is protected.
- **KEEP** ec2/eu-west-2/elastic-ip: `eipalloc-0d5bae537b16aece4` (35.179.203.86) - Associated EIP is protected.

### ebs

- **KEEP** ebs/ap-south-1/volume: `vol-0565b1380fd5b95af` - Attached volumes are protected.
- **KEEP** ebs/ap-south-1/volume: `vol-0470fcba474e66369` - Attached volumes are protected.
- **KEEP** ebs/ap-south-1/volume: `vol-0df4e7d2594aa7ef3` - Attached volumes are protected.
- **KEEP** ebs/af-south-1/volume: `vol-01c1a3af78626c883` - Attached volumes are protected.
- **KEEP** ebs/af-south-1/volume: `vol-03ecace0015529ecf` - Attached volumes are protected.
- **KEEP** ebs/af-south-1/volume: `vol-069f748509579be8f` - Attached volumes are protected.
- **KEEP** ebs/eu-west-2/volume: `vol-05b02fe2ee329505f` - Attached volumes are protected.
- **KEEP** ebs/eu-west-2/volume: `vol-05cc68f5d86b0ccc6` - Attached volumes are protected.

### elbv2

- **KEEP** elbv2/ap-south-1/load-balancer: `arn:aws:elasticloadbalancing:ap-south-1:368992683803:loadbalancer/app/mscqr-mumbai-alb/025ad0cb77546ee0` (mscqr-mumbai-alb) - Current DNS policy target.
- **KEEP** elbv2/ap-south-1/target-group: `arn:aws:elasticloadbalancing:ap-south-1:368992683803:targetgroup/mscqr-mumbai-frontend-tg/68982ccd4d8c26c1` (mscqr-mumbai-frontend-tg) - Current production routing dependency.
- **KEEP** elbv2/af-south-1/load-balancer: `arn:aws:elasticloadbalancing:af-south-1:368992683803:loadbalancer/app/mscqr-capetown-alb/b7defd5707ad181c` (mscqr-capetown-alb) - Current DNS policy target.
- **KEEP** elbv2/af-south-1/target-group: `arn:aws:elasticloadbalancing:af-south-1:368992683803:targetgroup/mscqr-capetown-frontend-tg/a9b43fd2d346e26d` (mscqr-capetown-frontend-tg) - Current production routing dependency.
- **KEEP** elbv2/eu-west-2/load-balancer: `arn:aws:elasticloadbalancing:eu-west-2:368992683803:loadbalancer/app/mscqr-alb-euw2/cda0292be6e39608` (mscqr-alb-euw2) - Current DNS policy target.
- **REVIEW_REQUIRED** elbv2/eu-west-2/target-group: `arn:aws:elasticloadbalancing:eu-west-2:368992683803:targetgroup/mscqr-backend-tg-euw2/6e970e6a19a28d75` (mscqr-backend-tg-euw2) - Target group needs listener/ASG/target-health review.
- **KEEP** elbv2/eu-west-2/target-group: `arn:aws:elasticloadbalancing:eu-west-2:368992683803:targetgroup/mscqr-frontend-tg-euw2/09ef3648e65481e6` (mscqr-frontend-tg-euw2) - Current production routing dependency.

### autoscaling

- **KEEP** autoscaling/ap-south-1/auto-scaling-group: `mscqr-mumbai-dr-asg` - Current regional DR/prod capacity.
- **KEEP** autoscaling/af-south-1/auto-scaling-group: `mscqr-capetown-dr-asg` - Current regional DR/prod capacity.

### launch-template

- **KEEP** launch-template/ap-south-1/launch-template: `lt-02570cc00f696ee4c` (mscqr-mumbai-dr-lt) - Current ASG launch template.
- **KEEP** launch-template/af-south-1/launch-template: `lt-04eeeecdf7ff884fe` (mscqr-capetown-dr-lt) - Current ASG launch template.

### security-group

- **KEEP** security-group/ap-south-1/security-group: `sg-0771ea7e59f7a49d4` (mscqr-ec2-web-sg-aps1) - Attached security groups are protected.
- **KEEP** security-group/ap-south-1/security-group: `sg-0ce45eda9cd11aa80` (mscqr-rds-sg-aps1) - Attached security groups are protected.
- **REVIEW_REQUIRED** security-group/ap-south-1/security-group: `sg-080278ac70122fce1` (default) - Security group requires ENI/reference console review.
- **KEEP** security-group/ap-south-1/security-group: `sg-0924027a22e96be48` (mscqr-mumbai-alb-sg) - Attached security groups are protected.
- **KEEP** security-group/ap-south-1/security-group: `sg-05a60dd45bc09e637` (mscqr-redis-sg-aps1) - Attached security groups are protected.
- **KEEP** security-group/af-south-1/security-group: `sg-0f768d6fc564123b1` (mscqr-rds-sg-afs1) - Attached security groups are protected.
- **REVIEW_REQUIRED** security-group/af-south-1/security-group: `sg-0d6af4df627e3fe43` (default) - Security group requires ENI/reference console review.
- **KEEP** security-group/af-south-1/security-group: `sg-061c4ffc734e1d149` (mscqr-redis-sg-afs1) - Attached security groups are protected.
- **KEEP** security-group/af-south-1/security-group: `sg-0ad358fd72d15bd3f` (mscqr-capetown-alb-sg) - Attached security groups are protected.
- **KEEP** security-group/af-south-1/security-group: `sg-0d8f560e4f6452aa5` (mscqr-ec2-web-sg-afs1) - Attached security groups are protected.
- **REVIEW_REQUIRED** security-group/eu-west-2/security-group: `sg-099af13ddef6abf9c` (rds_sg_mscqr_euw2) - Security group requires ENI/reference console review.
- **KEEP** security-group/eu-west-2/security-group: `sg-017d8b3b4be470165` (ec2-rds-1) - Attached security groups are protected.
- **KEEP** security-group/eu-west-2/security-group: `sg-0a7cbddd9770b220d` (mscqr-alb-sg-euw2) - Attached security groups are protected.
- **KEEP** security-group/eu-west-2/security-group: `sg-0e669ac5a54fdca9d` (mscqr-ec2-web-sg-euw2) - Attached security groups are protected.
- **REVIEW_REQUIRED** security-group/eu-west-2/security-group: `sg-0cf8506e2e846ef51` (launch-wizard-1) - Security group requires ENI/reference console review.
- **KEEP** security-group/eu-west-2/security-group: `sg-05128bf9006ff6ea9` (mscqr-github-runner-sg-euw2) - Attached security groups are protected.
- **REVIEW_REQUIRED** security-group/eu-west-2/security-group: `sg-0f70603411e227960` (default) - Security group requires ENI/reference console review.
- **KEEP** security-group/eu-west-2/security-group: `sg-0db971332ae625441` (mscqr-ecs-sg-euw2) - Attached security groups are protected.
- **KEEP** security-group/eu-west-2/security-group: `sg-07db1a9130c6df8d5` (rds-ec2-1) - Attached security groups are protected.
- **REVIEW_REQUIRED** security-group/us-east-1/security-group: `sg-03a7f996516587951` (default) - Security group requires ENI/reference console review.

### network-interface

- **KEEP** network-interface/ap-south-1/network-interface: `eni-06fff34694b568940` - Attached ENI is protected.
- **KEEP** network-interface/ap-south-1/network-interface: `eni-094f3f5cf0ab1fa8e` (ELB app/mscqr-mumbai-alb/025ad0cb77546ee0) - Attached ENI is protected.
- **KEEP** network-interface/ap-south-1/network-interface: `eni-0e7ca9fd62b446766` (ElastiCache mscqr-redis-aps1-primary-002) - Attached ENI is protected.
- **KEEP** network-interface/ap-south-1/network-interface: `eni-0b0c78c72654108b0` (ELB app/mscqr-mumbai-alb/025ad0cb77546ee0) - Attached ENI is protected.
- **KEEP** network-interface/ap-south-1/network-interface: `eni-01bcb43b1608b173e` - Attached ENI is protected.
- **KEEP** network-interface/ap-south-1/network-interface: `eni-0b6e91ad3c22886d2` (RDSNetworkInterface) - Attached ENI is protected.
- **KEEP** network-interface/ap-south-1/network-interface: `eni-0e8ea92f98fe0cd2f` (ElastiCache mscqr-redis-aps1-primary-001) - Attached ENI is protected.
- **KEEP** network-interface/ap-south-1/network-interface: `eni-02c00fca9c1e649e0` - Attached ENI is protected.
- **KEEP** network-interface/af-south-1/network-interface: `eni-0f44c7a9f12a7173a` (ELB app/mscqr-capetown-alb/b7defd5707ad181c) - Attached ENI is protected.
- **KEEP** network-interface/af-south-1/network-interface: `eni-06f2da01d828ec730` - Attached ENI is protected.
- **KEEP** network-interface/af-south-1/network-interface: `eni-03315255108a10d77` (ElastiCache mscqr-redis-afs1-primary-001) - Attached ENI is protected.
- **KEEP** network-interface/af-south-1/network-interface: `eni-00a2c0cfe854768c5` (RDSNetworkInterface) - Attached ENI is protected.
- **KEEP** network-interface/af-south-1/network-interface: `eni-059f35b271ff4ed7c` (ElastiCache mscqr-redis-afs1-primary-002) - Attached ENI is protected.
- **KEEP** network-interface/af-south-1/network-interface: `eni-06d9d12a42b3e1054` (ELB app/mscqr-capetown-alb/b7defd5707ad181c) - Attached ENI is protected.
- **KEEP** network-interface/af-south-1/network-interface: `eni-0f834b8389774d57e` - Attached ENI is protected.
- **KEEP** network-interface/af-south-1/network-interface: `eni-0afad4f6297c8dd80` - Attached ENI is protected.
- **KEEP** network-interface/eu-west-2/network-interface: `eni-076c3556f9a8097f2` (ElastiCache mscqr-redis-euw2-primary-001) - Attached ENI is protected.
- **KEEP** network-interface/eu-west-2/network-interface: `eni-0f7e94c94c71d04ba` (ELB app/mscqr-alb-euw2/cda0292be6e39608) - Attached ENI is protected.
- **KEEP** network-interface/eu-west-2/network-interface: `eni-04093255d4b517221` (Interface for NAT Gateway nat-0a51226e1f9190b2e) - Attached ENI is protected.
- **KEEP** network-interface/eu-west-2/network-interface: `eni-006057d805dacec95` - Attached ENI is protected.
- **KEEP** network-interface/eu-west-2/network-interface: `eni-0a5cd8d8da0c87d0a` (ELB app/mscqr-alb-euw2/cda0292be6e39608) - Attached ENI is protected.
- **KEEP** network-interface/eu-west-2/network-interface: `eni-0e08a5968473dfc3f` (ElastiCache mscqr-redis-euw2-primary-002) - Attached ENI is protected.
- **KEEP** network-interface/eu-west-2/network-interface: `eni-04f64b96fad9969ce` - Attached ENI is protected.
- **KEEP** network-interface/eu-west-2/network-interface: `eni-0f10f3b7d7d976e14` (RDSNetworkInterface) - Attached ENI is protected.
- **KEEP** network-interface/eu-west-2/network-interface: `eni-0bcec4c899f2fa5bc` (Interface for NAT Gateway nat-0be609dfc6ce97dc3) - Attached ENI is protected.

### rds

- **NEVER_DELETE_WITHOUT_BACKUP** rds/ap-south-1/db-instance: `mscqr-prod-db-aps1` - Never delete without backup/export/snapshot and explicit approval.
- **NEVER_DELETE_WITHOUT_BACKUP** rds/ap-south-1/manual-snapshot: `mscqr-prod-db-aps1-manual-2026-04-27` - Never delete without retention review and explicit approval.
- **NEVER_DELETE_WITHOUT_BACKUP** rds/af-south-1/db-instance: `mscqr-prod-db-afs1` - Never delete without backup/export/snapshot and explicit approval.
- **NEVER_DELETE_WITHOUT_BACKUP** rds/af-south-1/manual-snapshot: `mscqr-dr-capetown-restore-test-20260512-snapshot` - Never delete without retention review and explicit approval.
- **NEVER_DELETE_WITHOUT_BACKUP** rds/eu-west-2/db-instance: `mscqr-prod-db` - Never delete without backup/export/snapshot and explicit approval.
- **NEVER_DELETE_WITHOUT_BACKUP** rds/eu-west-2/manual-snapshot: `mscqr-dr-restore-test-20260511-snapshot` - Never delete without retention review and explicit approval.
- **NEVER_DELETE_WITHOUT_BACKUP** rds/eu-west-2/manual-snapshot: `mscqr-prod-db-post-deploy-2026-04-27` - Never delete without retention review and explicit approval.

### acm

- **KEEP** acm/ap-south-1/certificate: `arn:aws:acm:ap-south-1:368992683803:certificate/ac1be953-fdad-473e-8500-efbd02cb3715` (mscqr.com) - Certificate attached to active infrastructure.
- **KEEP** acm/af-south-1/certificate: `arn:aws:acm:af-south-1:368992683803:certificate/989885f0-4a26-4995-8b83-30be93ab2cfc` (mscqr.com) - Certificate attached to active infrastructure.
- **KEEP** acm/eu-west-2/certificate: `arn:aws:acm:eu-west-2:368992683803:certificate/297215d5-aebb-4c76-8323-564c147b0271` (mscqr.com) - Certificate attached to active infrastructure.

### cloudwatch

- **KEEP** cloudwatch/ap-south-1/alarm: `MSCQR-mumbai-ALB-5XX` - Current operational alarm candidate.
- **KEEP** cloudwatch/ap-south-1/alarm: `MSCQR-mumbai-EC2-CPU-70` - Current operational alarm candidate.
- **KEEP** cloudwatch/ap-south-1/alarm: `MSCQR-mumbai-Target-5XX` - Current operational alarm candidate.
- **KEEP** cloudwatch/ap-south-1/alarm: `MSCQR-mumbai-TargetResponseTime-p95` - Current operational alarm candidate.
- **KEEP** cloudwatch/ap-south-1/alarm: `MSCQR-mumbai-UnhealthyHosts` - Current operational alarm candidate.
- **KEEP** cloudwatch/ap-south-1/alarm: `mscqr-mumbai-ec2-cpu-high` - Current operational alarm candidate.
- **KEEP** cloudwatch/ap-south-1/alarm: `mscqr-mumbai-ec2-status-check-failed` - Current operational alarm candidate.
- **KEEP** cloudwatch/ap-south-1/alarm: `mscqr-mumbai-rds-cpu-high` - Current operational alarm candidate.
- **KEEP** cloudwatch/ap-south-1/alarm: `mscqr-mumbai-rds-db-connections-high` - Current operational alarm candidate.
- **KEEP** cloudwatch/ap-south-1/alarm: `mscqr-mumbai-rds-free-storage-low` - Current operational alarm candidate.
- **KEEP** cloudwatch/af-south-1/alarm: `MSCQR-capetown-ALB-5XX` - Current operational alarm candidate.
- **KEEP** cloudwatch/af-south-1/alarm: `MSCQR-capetown-EC2-CPU-70` - Current operational alarm candidate.
- **KEEP** cloudwatch/af-south-1/alarm: `MSCQR-capetown-Target-5XX` - Current operational alarm candidate.
- **KEEP** cloudwatch/af-south-1/alarm: `MSCQR-capetown-TargetResponseTime-p95` - Current operational alarm candidate.
- **KEEP** cloudwatch/af-south-1/alarm: `MSCQR-capetown-UnhealthyHosts` - Current operational alarm candidate.
- **KEEP** cloudwatch/af-south-1/alarm: `mscqr-capetown-ec2-cpu-high` - Current operational alarm candidate.
- **KEEP** cloudwatch/af-south-1/alarm: `mscqr-capetown-ec2-status-check-failed` - Current operational alarm candidate.
- **KEEP** cloudwatch/af-south-1/alarm: `mscqr-capetown-rds-cpu-high` - Current operational alarm candidate.
- **KEEP** cloudwatch/af-south-1/alarm: `mscqr-capetown-rds-db-connections-high` - Current operational alarm candidate.
- **KEEP** cloudwatch/af-south-1/alarm: `mscqr-capetown-rds-free-storage-low` - Current operational alarm candidate.
- **KEEP** cloudwatch/eu-west-2/alarm: `mscqr-ec2-cpu-high` - Current operational alarm candidate.
- **KEEP** cloudwatch/eu-west-2/alarm: `mscqr-ec2-status-check-failed` - Current operational alarm candidate.
- **KEEP** cloudwatch/eu-west-2/alarm: `mscqr-rds-cpu-high` - Current operational alarm candidate.
- **KEEP** cloudwatch/eu-west-2/alarm: `mscqr-rds-db-connections-high` - Current operational alarm candidate.
- **KEEP** cloudwatch/eu-west-2/alarm: `mscqr-rds-free-storage-low` - Current operational alarm candidate.

### ecs

- **REVIEW_REQUIRED** ecs/eu-west-2/cluster: `arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main` (mscqr-prod-euw2-main) - Review whether ECS release workflows still use this resource.

### ecr

- **REVIEW_REQUIRED** ecr/eu-west-2/repository: `mscqr-backend` - Do not remove images/repos without release history review.
- **REVIEW_REQUIRED** ecr/eu-west-2/repository: `mscqr-worker` - Do not remove images/repos without release history review.
- **REVIEW_REQUIRED** ecr/eu-west-2/repository: `mscqr-web` - Do not remove images/repos without release history review.

## Console Click Paths

- EC2 instances: AWS Console > EC2 > Instances.
- EBS volumes: AWS Console > EC2 > Elastic Block Store > Volumes.
- Snapshots: AWS Console > EC2 > Elastic Block Store > Snapshots.
- Elastic IPs: AWS Console > EC2 > Network & Security > Elastic IPs.
- Target groups: AWS Console > EC2 > Load Balancing > Target Groups.
- Load balancers: AWS Console > EC2 > Load Balancing > Load Balancers.
- Security groups: AWS Console > EC2 > Network & Security > Security Groups.
- RDS: AWS Console > RDS > Databases and Snapshots.
- S3: AWS Console > S3 > Buckets.
- IAM: AWS Console > IAM > Roles or Policies.
- ACM: AWS Console > Certificate Manager > Certificates.
- Route 53: AWS Console > Route 53 > Hosted zones > mscqr.com.

## Deletion Approval Protocol

1. Review one resource at a time.
2. Operator visually confirms the resource in AWS Console.
3. Screenshot/evidence is captured before any future action.
4. Capture screenshot before any future deletion or stop action.
5. A separate approval ledger is filled with resource ID, region, owner, evidence path, and approver.
6. Terminal action is run only after separate approval in a future pass.
7. Post-action inventory confirms the resource state changed as expected.

## Resources Not Eligible For Deletion In This Pass

- Route 53 apex geolocation records, www CNAME, MX, NS, SOA, TXT, DMARC, DKIM, SPF, and ACM validation records.
- Current Mumbai, Cape Town, and London ALBs and attached target groups.
- Current production ASGs, EC2 instances, GitHub runner instance, attached ENIs, attached security groups, and attached EBS volumes.
- RDS/Aurora instances, clusters, and snapshots without backup/export/snapshot review and explicit approval.
- Production S3 artifact buckets and ALB log buckets.
- Current GitHub deploy and auto-failover read-only IAM roles.
- Any ambiguous resource; ambiguity remains REVIEW_REQUIRED.

