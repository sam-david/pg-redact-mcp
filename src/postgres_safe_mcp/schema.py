"""Schema introspection and PII reporting."""

from __future__ import annotations

from dataclasses import dataclass

from .db import Database, TableInfo
from .redaction.detector import PiiDetector, PiiColumnInfo


@dataclass
class PiiColumnReport:
    """PII status report for a single column."""

    table_schema: str
    table_name: str
    column_name: str
    data_type: str
    pii_info: PiiColumnInfo | None
    masking_style: str


class SchemaManager:
    """Manages schema metadata and PII scanning."""

    def __init__(self) -> None:
        self._tables: dict[str, TableInfo] = {}

    async def load_schema(
        self, db: Database, allowed_schemas: list[str]
    ) -> dict[str, TableInfo]:
        """Fetch and cache schema metadata."""
        self._tables = await db.get_schema_info(allowed_schemas)
        return self._tables

    @property
    def tables(self) -> dict[str, TableInfo]:
        return self._tables

    def apply_heuristic_detection(self, detector: PiiDetector) -> None:
        """Run fast heuristic-only PII detection on all column names.

        This is instant (no DB queries) and catches most PII columns
        by name pattern alone. Presidio sample-based detection happens
        lazily on first query if needed.
        """
        for table_key, table_info in self._tables.items():
            for col in table_info.columns:
                cache_key = f"{table_key}.{col.column_name}"
                if cache_key not in detector._cache:
                    info = detector.detect_column_pii(col.column_name)
                    if info is not None:
                        detector._cache[cache_key] = info

    async def scan_table_pii(
        self,
        table_key: str,
        db: Database,
        detector: PiiDetector,
        sample_size: int = 100,
    ) -> None:
        """Run full PII detection (with sampling) on a single table."""
        table_info = self._tables.get(table_key)
        if not table_info:
            return
        col_names = [c.column_name for c in table_info.columns]

        async def sampler(col: str, _t=table_info) -> list[str]:
            return await db.sample_column(
                _t.name, col, schema=_t.schema, limit=sample_size
            )

        await detector.scan_table(table_key, col_names, sampler)

    def get_pii_report(
        self,
        detector: PiiDetector,
        default_masking_style: str = "partial",
        table_filter: str | None = None,
    ) -> list[PiiColumnReport]:
        """Generate a PII report for all (or one) table."""
        reports: list[PiiColumnReport] = []
        for table_key, table_info in self._tables.items():
            if table_filter and table_info.name != table_filter:
                # Also check schema.table format
                if table_filter != table_key:
                    continue
            for col in table_info.columns:
                pii_info = detector.get_cached_info(table_key, col.column_name)
                reports.append(
                    PiiColumnReport(
                        table_schema=table_info.schema,
                        table_name=table_info.name,
                        column_name=col.column_name,
                        data_type=col.data_type,
                        pii_info=pii_info,
                        masking_style=default_masking_style if pii_info else "none",
                    )
                )
        return reports

    def format_schema(
        self,
        detector: PiiDetector,
        default_masking_style: str = "partial",
        table_filter: str | None = None,
        show_pii: bool = True,
    ) -> str:
        """Format schema info as readable text."""
        reports = self.get_pii_report(detector, default_masking_style, table_filter)
        if not reports:
            if table_filter:
                return f"Table '{table_filter}' not found."
            return "No tables found."

        lines: list[str] = []
        current_table = ""
        for r in reports:
            table_label = f"{r.table_schema}.{r.table_name}"
            if table_label != current_table:
                if current_table:
                    lines.append("")
                lines.append(f"## {table_label}")
                current_table = table_label

            pii_label = ""
            if show_pii and r.pii_info:
                src = r.pii_info.source
                pii_label = (
                    f"  ⚠ PII:{r.pii_info.entity_type} "
                    f"({src}, {r.pii_info.confidence:.0%}) "
                    f"→ {r.masking_style}"
                )
            lines.append(f"  {r.column_name}: {r.data_type}{pii_label}")

        return "\n".join(lines)
