"""Command line interface for aws-webapp-cost-optimizer."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .analyzers import analyze_inventory
from .aws_collectors import AwsInventoryCollector, sample_inventory
from .evidence import create_evidence_dir, load_inventory, read_json, write_json, write_sha256_manifest
from .report import write_markdown_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aws-webapp-cost-optimizer")
    subparsers = parser.add_subparsers(dest="command", required=True)

    inventory_parser = subparsers.add_parser("inventory", help="Collect read-only inventory evidence")
    inventory_parser.add_argument("--config", required=True, help="Path to config YAML/JSON")
    inventory_parser.add_argument("--output-root", default="evidence", help="Directory where timestamped evidence is created")

    analyze_parser = subparsers.add_parser("analyze", help="Analyze an evidence directory")
    analyze_parser.add_argument("--evidence-dir", required=True)

    report_parser = subparsers.add_parser("report", help="Render Markdown report for an evidence directory")
    report_parser.add_argument("--evidence-dir", required=True)

    args = parser.parse_args(argv)
    if args.command == "inventory":
        return _inventory(args)
    if args.command == "analyze":
        return _analyze(args)
    if args.command == "report":
        return _report(args)
    parser.error("unknown command")
    return 2


def _inventory(args: argparse.Namespace) -> int:
    config = load_config(Path(args.config))
    app_name = str(config.get("app_name", "webapp"))
    regions = [str(item) for item in config.get("regions", ["us-east-1"])]
    output_root = Path(args.output_root)
    evidence_dir = create_evidence_dir(output_root, app_name)

    mode = str(config.get("mode", "sample")).lower()
    if mode in {"sample", "dry-run", "dry_run"}:
        inventory = sample_inventory(app_name=app_name, regions=regions)
    elif mode == "aws-readonly":
        inventory = AwsInventoryCollector(regions=regions, profile=config.get("profile")).collect()
        inventory["app_name"] = app_name
    else:
        raise ValueError(f"Unsupported inventory mode: {mode}")

    write_json(evidence_dir / "inventory.json", inventory)
    for region in regions:
        regional_resources = [item for item in inventory.get("resources", []) if item.get("region") == region]
        write_json(evidence_dir / region / "resources.json", {"region": region, "resources": regional_resources})
    write_json(evidence_dir / "metadata.json", {"config": _redacted_config(config), "evidence_dir": str(evidence_dir)})
    write_sha256_manifest(evidence_dir)
    print(evidence_dir)
    return 0


def _analyze(args: argparse.Namespace) -> int:
    evidence_dir = Path(args.evidence_dir)
    analysis = analyze_inventory(load_inventory(evidence_dir))
    write_json(evidence_dir / "analysis.json", analysis)
    write_sha256_manifest(evidence_dir)
    print(evidence_dir / "analysis.json")
    return 0


def _report(args: argparse.Namespace) -> int:
    evidence_dir = Path(args.evidence_dir)
    analysis_path = evidence_dir / "analysis.json"
    analysis = read_json(analysis_path) if analysis_path.exists() else analyze_inventory(load_inventory(evidence_dir))
    if not analysis_path.exists():
        write_json(analysis_path, analysis)
    write_markdown_report(evidence_dir / "report.md", analysis)
    write_sha256_manifest(evidence_dir)
    print(evidence_dir / "report.md")
    return 0


def load_config(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return json.loads(text)
    return _parse_simple_yaml(text)


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    data: dict[str, Any] = {}
    current_key: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if line.startswith("  - ") and current_key:
            data.setdefault(current_key, []).append(_coerce(line[4:].strip()))
            continue
        if ":" in line and not line.startswith(" "):
            key, value = line.split(":", 1)
            current_key = key.strip()
            value = value.strip()
            data[current_key] = [] if value == "" else _coerce(value)
    return data


def _coerce(value: str) -> Any:
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    if value.startswith("[") and value.endswith("]"):
        return [item.strip().strip('"').strip("'") for item in value[1:-1].split(",") if item.strip()]
    return value.strip('"').strip("'")


def _redacted_config(config: dict[str, Any]) -> dict[str, Any]:
    blocked = {"access_key", "secret_key", "token", "password"}
    return {key: ("<redacted>" if any(part in key.lower() for part in blocked) else value) for key, value in config.items()}


if __name__ == "__main__":
    raise SystemExit(main())
