"""Safety categories and mutation guards for AWS analysis workflows."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class SafetyCategory(str, Enum):
    UNUSED_DELETION_CANDIDATE = "unused deletion candidate"
    USED_BUT_OVERSIZED = "used but oversized"
    DR_POSTURE_DECISION_REQUIRED = "DR posture decision required"
    BLOCKED_BY_VALID_MODIFICATION_API = "blocked by AWS valid-modification API"
    MANUAL_APPROVAL_REQUIRED = "manual approval required"
    KEEP = "keep"
    OBSERVE_ONLY = "observe only"


MUTATING_OPERATION_PREFIXES = (
    "accept",
    "allocate",
    "associate",
    "attach",
    "authorize",
    "cancel",
    "copy",
    "create",
    "delete",
    "deregister",
    "detach",
    "disable",
    "disassociate",
    "enable",
    "failover",
    "import",
    "modify",
    "promote",
    "purchase",
    "put",
    "reboot",
    "register",
    "reject",
    "release",
    "remove",
    "replace",
    "restore",
    "revoke",
    "run",
    "scale",
    "start",
    "stop",
    "terminate",
    "update",
)

READONLY_OPERATION_PREFIXES = ("describe", "get", "list")


@dataclass(frozen=True)
class SafetyFinding:
    category: SafetyCategory
    severity: str
    message: str


def is_readonly_operation(operation_name: str) -> bool:
    normalized = operation_name.strip().replace("_", "-").lower()
    return normalized.startswith(READONLY_OPERATION_PREFIXES)


def is_mutating_operation(operation_name: str) -> bool:
    normalized = operation_name.strip().replace("_", "-").lower()
    return normalized.startswith(MUTATING_OPERATION_PREFIXES)


def assert_readonly_operation(operation_name: str) -> None:
    if is_mutating_operation(operation_name) or not is_readonly_operation(operation_name):
        raise ValueError(f"AWS operation is not allowed in read-only mode: {operation_name}")


def require_manual_approval(reason: str) -> SafetyFinding:
    return SafetyFinding(
        category=SafetyCategory.MANUAL_APPROVAL_REQUIRED,
        severity="high",
        message=reason,
    )
