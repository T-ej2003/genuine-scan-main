"""Evidence directory, JSON, and checksum helpers."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def create_evidence_dir(root: Path, app_name: str, stamp: str | None = None) -> Path:
    safe_app = "".join(char if char.isalnum() or char in "-_" else "-" for char in app_name.lower())
    evidence_dir = root / f"aws-webapp-cost-optimizer-{safe_app}-{stamp or utc_stamp()}"
    evidence_dir.mkdir(parents=True, exist_ok=False)
    return evidence_dir


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_sha256_manifest(root: Path, manifest_name: str = "SHA256SUMS.txt") -> Path:
    manifest = root / manifest_name
    rows: list[str] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file() and item.name != manifest_name):
        rows.append(f"{sha256_file(path)}  {path.relative_to(root)}")
    manifest.write_text("\n".join(rows) + ("\n" if rows else ""), encoding="utf-8")
    return manifest


def load_inventory(evidence_dir: Path) -> dict[str, Any]:
    inventory_path = evidence_dir / "inventory.json"
    if inventory_path.exists():
        return read_json(inventory_path)

    resources: list[dict[str, Any]] = []
    for path in sorted(evidence_dir.glob("*/resources.json")):
        region_doc = read_json(path)
        resources.extend(region_doc.get("resources", []))
    return {
        "app_name": "unknown",
        "generated_at": "",
        "regions": sorted({str(item.get("region", "")) for item in resources if item.get("region")}),
        "resources": resources,
    }
