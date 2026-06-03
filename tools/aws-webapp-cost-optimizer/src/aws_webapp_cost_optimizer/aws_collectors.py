"""Read-only AWS inventory collectors.

The default CLI example uses sample mode and does not call AWS. When real
collection is enabled, this module calls only describe/list/get-style APIs.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from .safety import assert_readonly_operation


RESOURCE_TYPES = (
    "ec2_instance",
    "eip",
    "nat_gateway",
    "route_table",
    "load_balancer",
    "target_group",
    "rds_instance",
    "rds_cluster",
    "elasticache_replication_group",
    "elasticache_cluster",
    "auto_scaling_group",
    "ebs_volume",
    "ebs_snapshot",
    "eni",
    "vpc_endpoint",
)


def sample_inventory(app_name: str = "example-webapp", regions: Iterable[str] | None = None) -> dict[str, Any]:
    selected_regions = list(regions or ["us-east-1", "eu-west-1"])
    primary = selected_regions[0]
    secondary = selected_regions[1] if len(selected_regions) > 1 else selected_regions[0]
    resources = [
        {
            "id": "i-0123456789example",
            "name": "example-webapp-primary",
            "region": primary,
            "service": "ec2",
            "type": "ec2_instance",
            "state": "running",
            "instance_type": "t3.large",
            "metrics": {"cpu_avg_14d": 4.2, "network_in_avg_14d": 1024},
            "tags": {"Role": "web"},
        },
        {
            "id": "eipalloc-exampleidle",
            "region": primary,
            "service": "ec2",
            "type": "eip",
            "association_id": None,
            "network_interface_id": None,
        },
        {
            "id": "nat-example-a",
            "region": primary,
            "service": "vpc",
            "type": "nat_gateway",
            "state": "available",
            "referenced_by_route_tables": ["rtb-private-a"],
        },
        {
            "id": "nat-example-unused",
            "region": primary,
            "service": "vpc",
            "type": "nat_gateway",
            "state": "available",
            "referenced_by_route_tables": [],
        },
        {
            "id": "rtb-private-a",
            "region": primary,
            "service": "vpc",
            "type": "route_table",
            "routes": [{"destination": "0.0.0.0/0", "target": "nat-example-a"}],
        },
        {
            "id": "arn:aws:elasticloadbalancing:region:123456789012:loadbalancer/app/example/abc",
            "name": "example-alb",
            "region": primary,
            "service": "elbv2",
            "type": "load_balancer",
            "scheme": "internet-facing",
            "state": "active",
        },
        {
            "id": "arn:aws:elasticloadbalancing:region:123456789012:targetgroup/example/def",
            "name": "example-web-targets",
            "region": primary,
            "service": "elbv2",
            "type": "target_group",
            "healthy_targets": 2,
            "unused": False,
        },
        {
            "id": "example-primary-db",
            "region": primary,
            "service": "rds",
            "type": "rds_instance",
            "class": "db.t4g.medium",
            "multi_az": False,
            "valid_modification_classes": [],
            "candidate_smaller_classes": ["db.t4g.small"],
        },
        {
            "id": "example-analytics-cluster",
            "region": primary,
            "service": "rds",
            "type": "rds_cluster",
            "engine": "aurora-postgresql",
            "role": "reporting",
        },
        {
            "id": "example-cache",
            "region": primary,
            "service": "elasticache",
            "type": "elasticache_replication_group",
            "node_type": "cache.t4g.medium",
            "automatic_failover": True,
            "multi_az": True,
            "metrics": {"cpu_avg_14d": 2.0, "memory_pct_avg_14d": 5.0, "evictions_14d": 0},
        },
        {
            "id": "example-cache-001",
            "region": primary,
            "service": "elasticache",
            "type": "elasticache_cluster",
            "node_type": "cache.t4g.medium",
            "replication_group_id": "example-cache",
        },
        {
            "id": "example-dr-asg",
            "region": secondary,
            "service": "autoscaling",
            "type": "auto_scaling_group",
            "min_size": 2,
            "desired_capacity": 2,
            "max_size": 4,
            "tags": {"Role": "dr"},
        },
        {
            "id": "vol-example-unused",
            "region": primary,
            "service": "ec2",
            "type": "ebs_volume",
            "state": "available",
            "size_gib": 100,
            "encrypted": True,
        },
        {
            "id": "snap-example-rollback",
            "region": primary,
            "service": "ec2",
            "type": "ebs_snapshot",
            "description": "rollback snapshot placeholder",
            "age_days": 14,
        },
        {
            "id": "eni-example-detached",
            "region": primary,
            "service": "ec2",
            "type": "eni",
            "status": "available",
        },
        {
            "id": "vpce-example-s3",
            "region": primary,
            "service": "vpc",
            "type": "vpc_endpoint",
            "service_name": "com.amazonaws.region.s3",
            "state": "available",
        },
    ]
    return {
        "app_name": app_name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "sample",
        "regions": selected_regions,
        "resource_types": list(RESOURCE_TYPES),
        "resources": resources,
    }


@dataclass
class AwsInventoryCollector:
    regions: list[str]
    profile: str | None = None

    def collect(self) -> dict[str, Any]:
        try:
            import boto3  # type: ignore
        except ImportError as exc:
            raise RuntimeError("boto3 is required for non-sample AWS inventory collection") from exc

        session_kwargs = {"profile_name": self.profile} if self.profile else {}
        session = boto3.Session(**session_kwargs)
        resources: list[dict[str, Any]] = []
        for region in self.regions:
            resources.extend(self._collect_region(session, region))
        return {
            "app_name": "aws-webapp",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "aws-readonly",
            "regions": self.regions,
            "resource_types": list(RESOURCE_TYPES),
            "resources": resources,
        }

    def _call(self, client: Any, operation: str, **kwargs: Any) -> dict[str, Any]:
        assert_readonly_operation(operation)
        method = getattr(client, operation)
        return method(**kwargs)

    def _collect_region(self, session: Any, region: str) -> list[dict[str, Any]]:
        ec2 = session.client("ec2", region_name=region)
        elbv2 = session.client("elbv2", region_name=region)
        rds = session.client("rds", region_name=region)
        elasticache = session.client("elasticache", region_name=region)
        autoscaling = session.client("autoscaling", region_name=region)

        resources: list[dict[str, Any]] = []
        resources.extend(self._ec2_resources(ec2, region))
        resources.extend(self._elbv2_resources(elbv2, region))
        resources.extend(self._rds_resources(rds, region))
        resources.extend(self._elasticache_resources(elasticache, region))
        resources.extend(self._asg_resources(autoscaling, region))
        return resources

    def _ec2_resources(self, ec2: Any, region: str) -> list[dict[str, Any]]:
        resources: list[dict[str, Any]] = []
        for reservation in self._call(ec2, "describe_instances").get("Reservations", []):
            for instance in reservation.get("Instances", []):
                resources.append({
                    "id": instance.get("InstanceId"),
                    "region": region,
                    "service": "ec2",
                    "type": "ec2_instance",
                    "state": instance.get("State", {}).get("Name"),
                    "instance_type": instance.get("InstanceType"),
                    "tags": _tags(instance.get("Tags", [])),
                })
        for address in self._call(ec2, "describe_addresses").get("Addresses", []):
            resources.append({
                "id": address.get("AllocationId") or address.get("PublicIp"),
                "region": region,
                "service": "ec2",
                "type": "eip",
                "association_id": address.get("AssociationId"),
                "network_interface_id": address.get("NetworkInterfaceId"),
                "instance_id": address.get("InstanceId"),
            })
        for nat in self._call(ec2, "describe_nat_gateways").get("NatGateways", []):
            resources.append({
                "id": nat.get("NatGatewayId"),
                "region": region,
                "service": "vpc",
                "type": "nat_gateway",
                "state": nat.get("State"),
            })
        for table in self._call(ec2, "describe_route_tables").get("RouteTables", []):
            resources.append({
                "id": table.get("RouteTableId"),
                "region": region,
                "service": "vpc",
                "type": "route_table",
                "routes": table.get("Routes", []),
                "tags": _tags(table.get("Tags", [])),
            })
        for volume in self._call(ec2, "describe_volumes").get("Volumes", []):
            resources.append({
                "id": volume.get("VolumeId"),
                "region": region,
                "service": "ec2",
                "type": "ebs_volume",
                "state": volume.get("State"),
                "size_gib": volume.get("Size"),
                "encrypted": volume.get("Encrypted"),
            })
        for snapshot in self._call(ec2, "describe_snapshots", OwnerIds=["self"]).get("Snapshots", []):
            resources.append({
                "id": snapshot.get("SnapshotId"),
                "region": region,
                "service": "ec2",
                "type": "ebs_snapshot",
                "description": snapshot.get("Description"),
                "encrypted": snapshot.get("Encrypted"),
            })
        for eni in self._call(ec2, "describe_network_interfaces").get("NetworkInterfaces", []):
            resources.append({
                "id": eni.get("NetworkInterfaceId"),
                "region": region,
                "service": "ec2",
                "type": "eni",
                "status": eni.get("Status"),
                "attachment": bool(eni.get("Attachment")),
            })
        for endpoint in self._call(ec2, "describe_vpc_endpoints").get("VpcEndpoints", []):
            resources.append({
                "id": endpoint.get("VpcEndpointId"),
                "region": region,
                "service": "vpc",
                "type": "vpc_endpoint",
                "service_name": endpoint.get("ServiceName"),
                "state": endpoint.get("State"),
            })
        return resources

    def _elbv2_resources(self, elbv2: Any, region: str) -> list[dict[str, Any]]:
        resources: list[dict[str, Any]] = []
        for lb in self._call(elbv2, "describe_load_balancers").get("LoadBalancers", []):
            resources.append({
                "id": lb.get("LoadBalancerArn"),
                "name": lb.get("LoadBalancerName"),
                "region": region,
                "service": "elbv2",
                "type": "load_balancer",
                "scheme": lb.get("Scheme"),
                "state": lb.get("State", {}).get("Code"),
            })
        for tg in self._call(elbv2, "describe_target_groups").get("TargetGroups", []):
            resources.append({
                "id": tg.get("TargetGroupArn"),
                "name": tg.get("TargetGroupName"),
                "region": region,
                "service": "elbv2",
                "type": "target_group",
                "load_balancer_arns": tg.get("LoadBalancerArns", []),
            })
        return resources

    def _rds_resources(self, rds: Any, region: str) -> list[dict[str, Any]]:
        resources = []
        for db in self._call(rds, "describe_db_instances").get("DBInstances", []):
            resources.append({
                "id": db.get("DBInstanceIdentifier"),
                "region": region,
                "service": "rds",
                "type": "rds_instance",
                "class": db.get("DBInstanceClass"),
                "engine": db.get("Engine"),
                "multi_az": db.get("MultiAZ"),
            })
        for cluster in self._call(rds, "describe_db_clusters").get("DBClusters", []):
            resources.append({
                "id": cluster.get("DBClusterIdentifier"),
                "region": region,
                "service": "rds",
                "type": "rds_cluster",
                "engine": cluster.get("Engine"),
                "multi_az": cluster.get("MultiAZ"),
            })
        return resources

    def _elasticache_resources(self, elasticache: Any, region: str) -> list[dict[str, Any]]:
        resources = []
        for group in self._call(elasticache, "describe_replication_groups").get("ReplicationGroups", []):
            resources.append({
                "id": group.get("ReplicationGroupId"),
                "region": region,
                "service": "elasticache",
                "type": "elasticache_replication_group",
                "status": group.get("Status"),
                "automatic_failover": group.get("AutomaticFailover"),
                "multi_az": group.get("MultiAZ"),
            })
        for cluster in self._call(elasticache, "describe_cache_clusters").get("CacheClusters", []):
            resources.append({
                "id": cluster.get("CacheClusterId"),
                "region": region,
                "service": "elasticache",
                "type": "elasticache_cluster",
                "status": cluster.get("CacheClusterStatus"),
                "node_type": cluster.get("CacheNodeType"),
            })
        return resources

    def _asg_resources(self, autoscaling: Any, region: str) -> list[dict[str, Any]]:
        resources = []
        for asg in self._call(autoscaling, "describe_auto_scaling_groups").get("AutoScalingGroups", []):
            resources.append({
                "id": asg.get("AutoScalingGroupName"),
                "region": region,
                "service": "autoscaling",
                "type": "auto_scaling_group",
                "min_size": asg.get("MinSize"),
                "desired_capacity": asg.get("DesiredCapacity"),
                "max_size": asg.get("MaxSize"),
                "tags": _tags(asg.get("Tags", [])),
            })
        return resources


def _tags(raw_tags: list[dict[str, Any]]) -> dict[str, str]:
    return {str(item.get("Key")): str(item.get("Value")) for item in raw_tags if item.get("Key")}
