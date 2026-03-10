"""MCP server with PostgreSQL tools and PII redaction."""

from __future__ import annotations

import json
import re
from typing import Annotated

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .config import Config
from .db import Database
from .redaction.detector import PiiDetector
from .redaction.engine import RedactionEngine
from .schema import SchemaManager

# Read-only SQL validation pattern
WRITE_PATTERN = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE|GRANT|REVOKE|COPY)\b",
    re.IGNORECASE,
)

mcp_server = FastMCP("postgres-safe")

# These get initialized by create_server()
_db: Database
_detector: PiiDetector
_engine: RedactionEngine
_schema_mgr: SchemaManager
_config: Config


def create_server(config: Config) -> FastMCP:
    """Initialize the server with a config and return the FastMCP instance."""
    global _db, _detector, _engine, _schema_mgr, _config

    _config = config
    _db = Database(config.connection_string)
    _detector = PiiDetector()
    _engine = RedactionEngine(
        detector=_detector,
        default_masking_style=config.default_masking_style,
    )
    _schema_mgr = SchemaManager()

    # Apply manual column rules from config
    for rule in config.column_rules:
        _detector.set_manual_override(
            table_key=f"public.{rule.table}" if "." not in rule.table else rule.table,
            column=rule.column,
            entity_type=rule.pii_type,
        )
        if rule.masking_style != "partial":
            table_key = (
                f"public.{rule.table}" if "." not in rule.table else rule.table
            )
            _engine.set_column_style(table_key, rule.column, rule.masking_style)

    return mcp_server


async def _ensure_initialized() -> None:
    """Connect to DB and scan schema on first use."""
    if _schema_mgr.tables:
        return
    await _db.connect()
    await _schema_mgr.load_schema(_db, _config.allowed_schemas)
    if _config.auto_detect:
        await _schema_mgr.scan_pii(_db, _detector, _config.sample_size)


@mcp_server.tool()
async def query(
    sql: Annotated[str, Field(description="SQL query to execute")],
    params: Annotated[
        dict | None, Field(description="Query parameters for parameterized queries")
    ] = None,
    reveal_columns: Annotated[
        list[str] | None,
        Field(
            description="Column names to show unmasked (e.g. ['email', 'name']). "
            "SECRET columns (encrypted passwords, tokens) cannot be revealed."
        ),
    ] = None,
    reveal_types: Annotated[
        list[str] | None,
        Field(
            description="PII entity types to show unmasked "
            "(e.g. ['EMAIL_ADDRESS', 'PERSON']). "
            "SECRET type cannot be revealed."
        ),
    ] = None,
) -> str:
    """Execute a SQL query with automatic PII redaction.

    Results are automatically masked based on detected PII types.
    Use reveal_columns or reveal_types to selectively unmask data
    when you need to see real values to solve a problem.

    Write operations (INSERT, UPDATE, DELETE, etc.) are only allowed
    when the server is configured with read_only: false.
    """
    is_write = bool(WRITE_PATTERN.search(sql))

    if is_write and _config.read_only:
        return (
            "Error: Write queries are not allowed. "
            "Server is in read-only mode (read_only: true). "
            "Set read_only: false in config to allow writes."
        )

    await _ensure_initialized()

    columns, rows, rowcount = await _db.execute_query(
        sql, params, max_rows=_config.max_rows, read_only=_config.read_only
    )

    # Write query — no result set, just rowcount
    if not columns and rowcount is not None:
        return f"Query executed successfully. Rows affected: {rowcount}"

    if not rows:
        return "Query returned 0 rows."

    # Redact
    redacted_rows, annotations = _engine.redact_results(
        columns=columns,
        rows=rows,
        reveal_columns=reveal_columns,
        reveal_types=reveal_types,
    )

    # Format output
    result_dicts = [dict(zip(columns, row)) for row in redacted_rows]
    output_parts = []

    # Add annotations header
    masked_cols = {k: v for k, v in annotations.items() if "MASKED" in v}
    unmasked_cols = {k: v for k, v in annotations.items() if "UNMASKED" in v}
    if masked_cols:
        output_parts.append(
            "PII masking applied: "
            + ", ".join(f"{k} {v}" for k, v in masked_cols.items())
        )
    if unmasked_cols:
        output_parts.append(
            "Revealed (unmasked): "
            + ", ".join(f"{k}" for k in unmasked_cols)
        )

    output_parts.append(f"Rows: {len(result_dicts)}")
    output_parts.append(json.dumps(result_dicts, indent=2, default=str))

    return "\n".join(output_parts)


@mcp_server.tool()
async def describe_schema(
    table: Annotated[
        str | None,
        Field(description="Table name to describe, or omit for all tables"),
    ] = None,
    show_pii: Annotated[
        bool, Field(description="Show PII detection status for each column")
    ] = True,
) -> str:
    """List database tables and columns with their types and PII detection status."""
    await _ensure_initialized()
    return _schema_mgr.format_schema(
        detector=_detector,
        default_masking_style=_config.default_masking_style,
        table_filter=table,
        show_pii=show_pii,
    )


@mcp_server.tool()
async def explain_query(
    sql: Annotated[str, Field(description="SQL query to get the execution plan for")],
) -> str:
    """Show the PostgreSQL execution plan for a query (EXPLAIN)."""
    if WRITE_PATTERN.search(sql) and _config.read_only:
        return (
            "Error: Cannot EXPLAIN write queries in read-only mode. "
            "Set read_only: false in config to allow this."
        )

    await _ensure_initialized()
    return await _db.execute_explain(sql)


@mcp_server.tool()
async def configure_masking(
    table: Annotated[str, Field(description="Table name (e.g. 'users' or 'public.users')")],
    column: Annotated[str, Field(description="Column name")],
    masking_style: Annotated[
        str,
        Field(description="Masking style: 'partial', 'full', 'pseudonymize', or 'none'"),
    ] = "partial",
    pii_type: Annotated[
        str | None,
        Field(
            description="PII entity type override (e.g. 'EMAIL_ADDRESS', 'PERSON', 'none')"
        ),
    ] = None,
) -> str:
    """Configure masking for a specific column (runtime override, not persisted)."""
    table_key = f"public.{table}" if "." not in table else table

    if pii_type:
        _detector.set_manual_override(table_key, column, pii_type)

    if masking_style:
        _engine.set_column_style(table_key, column, masking_style)

    return (
        f"Updated masking for {table_key}.{column}: "
        f"style={masking_style}"
        + (f", pii_type={pii_type}" if pii_type else "")
    )


@mcp_server.tool()
async def list_masking_rules() -> str:
    """Show all active PII detection results and masking rules."""
    await _ensure_initialized()

    cached = _detector.get_all_cached()
    if not cached:
        return "No PII classifications cached yet. Run a query or describe_schema first."

    lines = ["Active PII masking rules:", ""]
    for key, info in sorted(cached.items()):
        if info is None:
            lines.append(f"  {key}: NOT PII (manually excluded)")
        else:
            style = _engine.get_masking_style(
                ".".join(key.split(".")[:-1]),  # table_key
                key.split(".")[-1],  # column
            )
            lines.append(
                f"  {key}: {info.entity_type} "
                f"({info.source}, {info.confidence:.0%}) → {style}"
            )

    return "\n".join(lines)
