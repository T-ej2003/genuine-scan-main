"""Markdown report rendering."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def render_markdown_report(analysis: dict[str, Any]) -> str:
    lines = [
        f"# AWS Web App Cost Optimizer Report: {analysis.get('app_name', 'unknown')}",
        "",
        "This report is generated from evidence only. It is not approval to mutate AWS resources.",
        "",
        "## Summary",
        "",
        "| Category | Count |",
        "| --- | ---: |",
    ]
    for category, count in analysis.get("summary", {}).items():
        lines.append(f"| {category} | {count} |")
    lines.extend([
        "",
        "## Findings",
        "",
        "| Region | Service | Resource | Category | Risk | Recommendation |",
        "| --- | --- | --- | --- | --- | --- |",
    ])
    for finding in analysis.get("findings", []):
        lines.append(
            "| {region} | {service} | {resource_type} `{resource_id}` | {category} | {risk} | {recommendation} |".format(
                **{key: _cell(value) for key, value in finding.items()}
            )
        )
    lines.extend([
        "",
        "## Safety Gate",
        "",
        "- Default workflow is read-only inventory, analysis, report, review, then separate approval.",
        "- Deletion candidates are only candidates; owner approval, backup/rollback evidence, and post-change checks are mandatory.",
        "- Databases, snapshots, DR ASGs, load balancers, and production entry points should default to keep.",
        "",
    ])
    return "\n".join(lines)


def write_markdown_report(path: Path, analysis: dict[str, Any]) -> Path:
    path.write_text(render_markdown_report(analysis), encoding="utf-8")
    return path


def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")
