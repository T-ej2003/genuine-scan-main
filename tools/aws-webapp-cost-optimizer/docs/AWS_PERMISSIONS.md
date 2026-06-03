# AWS Permissions

Use the smallest practical read-only permissions. The collector is designed around these API families:

- STS: `GetCallerIdentity`
- EC2/VPC: `DescribeInstances`, `DescribeAddresses`, `DescribeNatGateways`, `DescribeRouteTables`, `DescribeVolumes`, `DescribeSnapshots`, `DescribeNetworkInterfaces`, `DescribeVpcEndpoints`
- ELBv2: `DescribeLoadBalancers`, `DescribeTargetGroups`
- RDS: `DescribeDBInstances`, `DescribeDBClusters`, `DescribeValidDBInstanceModifications`
- ElastiCache: `DescribeReplicationGroups`, `DescribeCacheClusters`
- Auto Scaling: `DescribeAutoScalingGroups`
- CloudWatch and Cost Explorer adapters are planned as read-only evidence sources.

Do not grant mutation permissions to an inventory role.
