"""PostgreSQL connection and query execution."""

from __future__ import annotations

from dataclasses import dataclass

import psycopg


@dataclass
class ColumnInfo:
    """Metadata about a database column."""

    table_schema: str
    table_name: str
    column_name: str
    data_type: str
    is_nullable: bool


@dataclass
class TableInfo:
    """Metadata about a database table."""

    schema: str
    name: str
    columns: list[ColumnInfo]


class Database:
    """Manages a read-only PostgreSQL connection."""

    def __init__(self, connection_string: str) -> None:
        self._connection_string = connection_string
        self._conn: psycopg.Connection | None = None

    async def connect(self) -> None:
        self._conn = await psycopg.AsyncConnection.connect(
            self._connection_string,
            autocommit=True,
        )

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None

    def _ensure_connected(self) -> psycopg.AsyncConnection:
        if not self._conn:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self._conn

    async def execute_query(
        self,
        sql: str,
        params: dict | None = None,
        max_rows: int = 1000,
        read_only: bool = True,
    ) -> tuple[list[str], list[list], int | None]:
        """Execute a query. Returns (column_names, rows, rowcount).

        When read_only=True, the transaction is set to READ ONLY.
        For write queries, rowcount is the number of affected rows.
        For SELECT queries, rows contain the result set.
        """
        conn = self._ensure_connected()
        async with conn.transaction():
            if read_only:
                await conn.execute("SET TRANSACTION READ ONLY")
            cursor = await conn.execute(sql, params)
            # SELECT-like queries have a description
            if cursor.description:
                columns = [desc.name for desc in cursor.description]
                rows = await cursor.fetchmany(max_rows)
                return columns, [list(row) for row in rows], None
            else:
                # Write queries (INSERT/UPDATE/DELETE) — return rowcount
                return [], [], cursor.rowcount

    async def execute_explain(self, sql: str) -> str:
        """Run EXPLAIN on a query and return the plan text."""
        conn = self._ensure_connected()
        async with conn.transaction():
            await conn.execute("SET TRANSACTION READ ONLY")
            cursor = await conn.execute(f"EXPLAIN (FORMAT TEXT) {sql}")
            rows = await cursor.fetchall()
        return "\n".join(row[0] for row in rows)

    async def get_schema_info(
        self, allowed_schemas: list[str]
    ) -> dict[str, TableInfo]:
        """Fetch table/column metadata from information_schema."""
        conn = self._ensure_connected()
        query = """
            SELECT table_schema, table_name, column_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE table_schema = ANY(%s)
            ORDER BY table_schema, table_name, ordinal_position
        """
        cursor = await conn.execute(query, [allowed_schemas])
        rows = await cursor.fetchall()

        tables: dict[str, TableInfo] = {}
        for schema, table, col_name, data_type, nullable in rows:
            key = f"{schema}.{table}"
            if key not in tables:
                tables[key] = TableInfo(schema=schema, name=table, columns=[])
            tables[key].columns.append(
                ColumnInfo(
                    table_schema=schema,
                    table_name=table,
                    column_name=col_name,
                    data_type=data_type,
                    is_nullable=nullable == "YES",
                )
            )
        return tables

    async def sample_column(
        self,
        table: str,
        column: str,
        schema: str = "public",
        limit: int = 100,
    ) -> list[str]:
        """Fetch sample non-null values from a column for PII detection."""
        conn = self._ensure_connected()
        # Use identifier quoting to prevent SQL injection
        query = (
            f"SELECT DISTINCT {psycopg.sql.Identifier(column).as_string(conn)}::text "
            f"FROM {psycopg.sql.Identifier(schema, table).as_string(conn)} "
            f"WHERE {psycopg.sql.Identifier(column).as_string(conn)} IS NOT NULL "
            f"LIMIT %s"
        )
        cursor = await conn.execute(query, [limit])
        rows = await cursor.fetchall()
        return [row[0] for row in rows if row[0]]
