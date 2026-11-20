"""Quality report collector for data normalization.

Tracks rows read, duplicates removed, values fixed per rule, rows rejected with
reasons, and columns unavailable in the source per normalized table.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class TableQualityStats:
    """Quality statistics collected for a single canonical table."""

    table_name: str
    status: str = "available"  # "available" or "not available in source"
    rows_read: int = 0
    duplicates_removed: int = 0
    rows_output: int = 0
    values_fixed: dict[str, int] = field(default_factory=dict)
    rows_rejected: dict[str, int] = field(default_factory=dict)
    columns_unavailable: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def record_fix(self, rule_name: str, count: int = 1) -> None:
        """Increment count for a value normalization rule."""
        if count > 0:
            self.values_fixed[rule_name] = self.values_fixed.get(rule_name, 0) + count

    def record_rejection(self, reason: str, count: int = 1) -> None:
        """Increment count for rejected rows with reason."""
        if count > 0:
            self.rows_rejected[reason] = self.rows_rejected.get(reason, 0) + count


class QualityReporter:
    """Collects per-table quality statistics and formats reports."""

    def __init__(self, dataset_name: str) -> None:
        self.dataset_name = dataset_name
        self.tables: dict[str, TableQualityStats] = {}

    def get_or_create_table(self, table_name: str) -> TableQualityStats:
        """Retrieve existing table stats or initialize a new record."""
        if table_name not in self.tables:
            self.tables[table_name] = TableQualityStats(table_name=table_name)
        return self.tables[table_name]

    def mark_unavailable(self, table_name: str, reason: str = "not available in source") -> None:
        """Mark a required canonical table as completely absent in source."""
        stats = self.get_or_create_table(table_name)
        stats.status = "not available in source"
        stats.notes.append(reason)

    def to_dict(self) -> dict[str, Any]:
        """Convert collected statistics to a serializable dictionary."""
        return {
            "dataset": self.dataset_name,
            "total_tables": len(self.tables),
            "tables": {name: asdict(stats) for name, stats in sorted(self.tables.items())},
        }

    def to_markdown(self) -> str:
        """Format quality statistics as a human-readable Markdown report."""
        lines = [
            f"# Data Normalization Quality Report: {self.dataset_name}",
            "",
            "## Summary of Normalized Tables",
            "",
            "| Table | Status | Rows Read | Duplicates Dropped | Rows Output | Unavailable Columns | Fixes Applied |",
            "|---|---|---|---|---|---|---|",
        ]
        for name, stats in sorted(self.tables.items()):
            unavail_cols_str = (
                ", ".join(stats.columns_unavailable) if stats.columns_unavailable else "-"
            )
            fixes_count = sum(stats.values_fixed.values())
            lines.append(
                f"| `{name}` | {stats.status} | {stats.rows_read:,} | {stats.duplicates_removed:,} | "
                f"{stats.rows_output:,} | {unavail_cols_str} | {fixes_count:,} |"
            )

        lines.extend(["", "## Detailed Table Statistics", ""])
        for name, stats in sorted(self.tables.items()):
            lines.append(f"### `{name}`")
            lines.append(f"- **Status:** {stats.status}")
            lines.append(f"- **Rows read:** {stats.rows_read:,}")
            lines.append(f"- **Duplicates removed:** {stats.duplicates_removed:,}")
            lines.append(f"- **Rows written:** {stats.rows_output:,}")
            if stats.columns_unavailable:
                lines.append(
                    f"- **Columns not in source (left null):** {', '.join(f'`{c}`' for c in stats.columns_unavailable)}"
                )
            if stats.values_fixed:
                lines.append("- **Values normalized by rule:**")
                for rule, cnt in sorted(stats.values_fixed.items()):
                    lines.append(f"  - `{rule}`: {cnt:,}")
            if stats.rows_rejected:
                lines.append("- **Rows rejected:**")
                for reason, cnt in sorted(stats.rows_rejected.items()):
                    lines.append(f"  - `{reason}`: {cnt:,}")
            if stats.notes:
                lines.append("- **Notes:**")
                for note in stats.notes:
                    lines.append(f"  - {note}")
            lines.append("")

        return "\n".join(lines)

    def write_reports(self, output_dir: Path | str) -> tuple[Path, Path]:
        """Save report as both quality_report.json and quality_report.md."""
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        json_path = out_path / "quality_report.json"
        md_path = out_path / "quality_report.md"

        json_path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        md_path.write_text(self.to_markdown(), encoding="utf-8")

        return json_path, md_path
