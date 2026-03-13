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
    """Connect to DB and load schema on first use.

    PII scanning is NOT done eagerly — with large schemas (hundreds of tables),
    scanning every column upfront would take minutes. Instead, columns are
    classified lazily when they first appear in query results.
    """
    if _schema_mgr.tables:
        return
    await _db.connect()
    await _schema_mgr.load_schema(_db, _config.allowed_schemas)
    # Apply heuristic-only detection to schema column names (no sampling, instant)
    if _config.auto_detect:
        _schema_mgr.apply_heuristic_detection(_detector)


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

    IMPORTANT: Before writing a query, use describe_schema to check the
    table's actual column names. Do NOT guess column names — schemas vary
    widely and incorrect guesses waste round trips.

    IMPORTANT: All PII columns are masked by default. You should keep data
    masked unless the user's request CANNOT be answered without seeing the
    real values. Follow these guidelines:

    KEEP MASKED (do not use reveal_columns/reveal_types):
    - Browsing or exploring data ("show me the users table")
    - Aggregate queries ("how many users signed up last month?")
    - Pattern analysis ("what's the distribution of email domains?")
    - Debugging non-PII issues ("why is this record's status wrong?")

    REVEAL only when the user explicitly asks to see PII values:
    - "What is John's email address?" → reveal_columns: ["email"]
    - "Show me the full name of user 42" → reveal_columns: ["first_name", "last_name"]
    - "I need to see the real phone numbers" → reveal_types: ["PHONE_NUMBER"]

    When in doubt, keep it masked. The user can always ask you to reveal.

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

    return _format_results(columns, redacted_rows, annotations, _config.max_rows)


def _format_results(
    columns: list[str],
    rows: list[list],
    annotations: dict[str, str],
    max_rows: int,
) -> str:
    """Format query results for optimal AI consumption.

    Uses markdown table for structured readability and token efficiency.
    Falls back to TSV for very wide results (>8 columns).
    """
    output_parts: list[str] = []

    # Metadata header
    masked_cols = {k: v for k, v in annotations.items() if "MASKED" in v}
    unmasked_cols = {k: v for k, v in annotations.items() if "UNMASKED" in v}
    if masked_cols:
        output_parts.append(
            "PII masked: "
            + ", ".join(f"{k} ({v.strip('[]')})" for k, v in masked_cols.items())
        )
    if unmasked_cols:
        output_parts.append(
            "Revealed: " + ", ".join(unmasked_cols)
        )

    truncated = len(rows) >= max_rows
    row_label = f"{len(rows)} rows" + (" (truncated)" if truncated else "")
    output_parts.append(row_label)
    output_parts.append("")

    # Format as markdown table (compact, easy for LLMs to parse)
    # For very wide results, use TSV to avoid unwieldy tables
    if len(columns) > 8:
        output_parts.append(_format_tsv(columns, rows))
    else:
        output_parts.append(_format_markdown_table(columns, rows))

    return "\n".join(output_parts)


MAX_CELL_LENGTH = 500


def _format_markdown_table(columns: list[str], rows: list[list]) -> str:
    """Format as a markdown table."""
    str_rows = [[str(v) if v is not None else "NULL" for v in row] for row in rows]

    # Header
    header = "| " + " | ".join(columns) + " |"
    separator = "| " + " | ".join("---" for _ in columns) + " |"

    # Rows (only truncate very large values to protect context window)
    lines = [header, separator]
    for row in str_rows:
        cells = []
        for val in row:
            if len(val) > MAX_CELL_LENGTH:
                val = val[:MAX_CELL_LENGTH] + "... (truncated)"
            cells.append(val)
        lines.append("| " + " | ".join(cells) + " |")

    return "\n".join(lines)


def _format_tsv(columns: list[str], rows: list[list]) -> str:
    """Format as TSV for wide results — compact and parseable."""
    lines = ["\t".join(columns)]
    for row in rows:
        cells = []
        for v in row:
            val = str(v) if v is not None else "NULL"
            if len(val) > MAX_CELL_LENGTH:
                val = val[:MAX_CELL_LENGTH] + "... (truncated)"
            cells.append(val)
        lines.append("\t".join(cells))
    return "\n".join(lines)


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
    """List database tables and columns with their types and PII detection status.

    Call this FIRST before writing any query to check actual column names.
    Always pass a table name to see its columns — this is fast and returns
    only the columns you need. Omitting the table name lists ALL tables
    which can be very large; only do this if you need to search for a table.
    """
    await _ensure_initialized()

    # When listing all tables without a filter, just show table names
    # to avoid dumping thousands of columns
    if table is None:
        table_names = sorted(
            f"{t.schema}.{t.name}" for t in _schema_mgr.tables.values()
        )
        return (
            f"{len(table_names)} tables found. "
            "Pass a table name to see its columns.\n\n"
            + "\n".join(table_names)
        )

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
