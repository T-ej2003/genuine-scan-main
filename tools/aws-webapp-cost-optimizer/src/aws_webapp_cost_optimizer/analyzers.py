"""Conservative cost optimization analyzers."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

from .safety import SafetyCategory


@dataclass(frozen=True)
class Finding:
    region: str
    service: str
    resource_type: str
    resource_id: str
    category: SafetyCategory
    risk: str
    reason: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["category"] = self.category.value
        return payload


def analyze_inventory(inventory: dict[str, Any]) -> dict[str, Any]:
    findings = [analyze_resource(resource) for resource in inventory.get("resources", [])]
    return {
        "app_name": inventory.get("app_name", "unknown"),
        "generated_at": inventory.get("generated_at", ""),
        "source_mode": inventory.get("mode", "unknown"),
        "regions": inventory.get("regions", []),
        "findings": [finding.to_dict() for finding in findings],
        "summary": summarize_findings(findings),
    }


def analyze_resource(resource: dict[str, Any]) -> Finding:
    resource_type = str(resource.get("type", "unknown"))
    if resource_type == "eip":
        if not resource.get("association_id") and not resource.get("network_interface_id"):
            return _finding(resource, SafetyCategory.UNUSED_DELETION_CANDIDATE, "medium", "Elastic IP is not associated.", "Verify ownership, DNS, and rollback need before release approval.")
        return _finding(resource, SafetyCategory.KEEP, "low", "Elastic IP is associated.", "Keep unless dependency review proves replacement.")
    if resource_type == "nat_gateway":
        refs = resource.get("referenced_by_route_tables")
        if refs == []:
            return _finding(resource, SafetyCategory.UNUSED_DELETION_CANDIDATE, "high", "NAT gateway has no recorded private route table references.", "Capture route tables, egress requirements, and rollback plan before deletion approval.")
        return _finding(resource, SafetyCategory.MANUAL_APPROVAL_REQUIRED, "high", "NAT gateway can be a single point of egress.", "Review NAT bytes, route tables, and endpoint alternatives.")
    if resource_type == "ec2_instance":
        metrics = resource.get("metrics", {})
        if resource.get("state") == "running" and metrics.get("cpu_avg_14d", 100) < 10:
            return _finding(resource, SafetyCategory.USED_BUT_OVERSIZED, "medium", "Running instance has low average CPU in available metrics.", "Check peak metrics, memory, disk, and workload role before resize approval.")
        return _finding(resource, SafetyCategory.MANUAL_APPROVAL_REQUIRED, "medium", "EC2 instance requires workload ownership review.", "Classify production, DR, runner, batch, or unknown before action.")
    if resource_type in {"load_balancer", "target_group"}:
        if resource.get("unused") is True or resource.get("load_balancer_arns") == []:
            return _finding(resource, SafetyCategory.UNUSED_DELETION_CANDIDATE, "medium", "Load balancer resource appears unattached.", "Confirm DNS/listener/ASG references before removal approval.")
        return _finding(resource, SafetyCategory.KEEP, "high", "Load balancer resources may be live traffic entry points.", "Keep unless traffic and DNS evidence prove unused.")
    if resource_type in {"rds_instance", "rds_cluster"}:
        if resource.get("candidate_smaller_classes") and resource.get("valid_modification_classes") == []:
            return _finding(resource, SafetyCategory.BLOCKED_BY_VALID_MODIFICATION_API, "high", "Smaller classes may be orderable, but valid-modification API returned no approved target.", "Do not modify class; recapture valid modifications later.")
        return _finding(resource, SafetyCategory.MANUAL_APPROVAL_REQUIRED, "high", "Database resources are stateful and require backup/restore proof.", "Review metrics, backups, restore path, and maintenance window.")
    if resource_type in {"elasticache_replication_group", "elasticache_cluster"}:
        metrics = resource.get("metrics", {})
        if metrics and metrics.get("cpu_avg_14d", 100) < 10 and metrics.get("memory_pct_avg_14d", 100) < 20 and metrics.get("evictions_14d", 1) == 0:
            return _finding(resource, SafetyCategory.USED_BUT_OVERSIZED, "medium", "Cache metrics show low CPU, low memory, and no evictions.", "Review sessions/rate limits/failover before node class or topology change.")
        return _finding(resource, SafetyCategory.MANUAL_APPROVAL_REQUIRED, "high", "Cache may support sessions, queues, locks, or rate limits.", "Do not delete without app dependency review.")
    if resource_type == "auto_scaling_group":
        tags = {str(k).lower(): str(v).lower() for k, v in resource.get("tags", {}).items()}
        if "dr" in " ".join(tags.values()):
            return _finding(resource, SafetyCategory.DR_POSTURE_DECISION_REQUIRED, "high", "ASG appears to be part of DR posture.", "Do not reduce without explicit RTO/RPO and regional capacity decision.")
        return _finding(resource, SafetyCategory.MANUAL_APPROVAL_REQUIRED, "medium", "ASG capacity changes affect availability.", "Review desired/min/max, warmup, target health, and release flows.")
    if resource_type == "ebs_volume":
        if resource.get("state") == "available":
            return _finding(resource, SafetyCategory.UNUSED_DELETION_CANDIDATE, "medium", "EBS volume is unattached.", "Snapshot/owner/restore proof required before deletion approval.")
        return _finding(resource, SafetyCategory.KEEP, "medium", "EBS volume is attached or state is unknown.", "Keep until attachment and workload are reviewed.")
    if resource_type == "ebs_snapshot":
        return _finding(resource, SafetyCategory.MANUAL_APPROVAL_REQUIRED, "medium", "Snapshots may be rollback or compliance evidence.", "Apply retention policy only after owner and restore-purpose review.")
    if resource_type == "eni":
        if resource.get("status") == "available":
            return _finding(resource, SafetyCategory.UNUSED_DELETION_CANDIDATE, "medium", "Network interface appears detached.", "Confirm service ownership before deletion approval.")
        return _finding(resource, SafetyCategory.KEEP, "medium", "Network interface is attached or in use.", "Keep unless dependency review proves unused.")
    if resource_type == "vpc_endpoint":
        return _finding(resource, SafetyCategory.OBSERVE_ONLY, "low", "VPC endpoint may reduce NAT egress cost.", "Review missing endpoints for S3/ECR/SSM/CloudWatch before adding infrastructure.")
    return _finding(resource, SafetyCategory.MANUAL_APPROVAL_REQUIRED, "medium", "Unknown resource type.", "Add a typed analyzer before taking action.")


def summarize_findings(findings: list[Finding]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for finding in findings:
        key = finding.category.value
        summary[key] = summary.get(key, 0) + 1
    return dict(sorted(summary.items()))


def _finding(resource: dict[str, Any], category: SafetyCategory, risk: str, reason: str, recommendation: str) -> Finding:
    return Finding(
        region=str(resource.get("region", "unknown")),
        service=str(resource.get("service", "unknown")),
        resource_type=str(resource.get("type", "unknown")),
        resource_id=str(resource.get("id") or resource.get("name") or "unknown"),
        category=category,
        risk=risk,
        reason=reason,
        recommendation=recommendation,
    )
