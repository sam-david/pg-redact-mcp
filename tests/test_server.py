"""Tests for the MCP server tool handlers."""

import re

from postgres_safe_mcp.server import WRITE_PATTERN, _format_results


class TestWritePatternDetection:
    """Tests that WRITE_PATTERN correctly identifies write vs read queries."""
    def test_rejects_insert(self):
        assert WRITE_PATTERN.search("INSERT INTO users VALUES (1)")

    def test_rejects_update(self):
        assert WRITE_PATTERN.search("UPDATE users SET name = 'x'")

    def test_rejects_delete(self):
        assert WRITE_PATTERN.search("DELETE FROM users WHERE id = 1")

    def test_rejects_drop(self):
        assert WRITE_PATTERN.search("DROP TABLE users")

    def test_rejects_alter(self):
        assert WRITE_PATTERN.search("ALTER TABLE users ADD COLUMN x int")

    def test_rejects_truncate(self):
        assert WRITE_PATTERN.search("TRUNCATE users")

    def test_rejects_create(self):
        assert WRITE_PATTERN.search("CREATE TABLE foo (id int)")

    def test_rejects_grant(self):
        assert WRITE_PATTERN.search("GRANT ALL ON users TO admin")

    def test_rejects_copy(self):
        assert WRITE_PATTERN.search("COPY users TO '/tmp/out.csv'")

    def test_allows_select(self):
        assert WRITE_PATTERN.search("SELECT * FROM users") is None

    def test_allows_select_with_subquery(self):
        assert WRITE_PATTERN.search(
            "SELECT * FROM (SELECT id FROM users) t"
        ) is None

    def test_allows_with_cte(self):
        assert WRITE_PATTERN.search(
            "WITH active AS (SELECT * FROM users WHERE active) SELECT * FROM active"
        ) is None

    def test_allows_explain(self):
        assert WRITE_PATTERN.search("EXPLAIN SELECT * FROM users") is None

    def test_case_insensitive(self):
        assert WRITE_PATTERN.search("insert into users values (1)")
        assert WRITE_PATTERN.search("Insert Into users Values (1)")

    def test_detects_write_for_all_dangerous_keywords(self):
        """Ensure all dangerous SQL keywords are detected."""
        dangerous = [
            "INSERT", "UPDATE", "DELETE", "DROP", "ALTER",
            "TRUNCATE", "CREATE", "GRANT", "REVOKE", "COPY",
        ]
        for keyword in dangerous:
            assert WRITE_PATTERN.search(f"{keyword} something"), (
                f"Failed to detect: {keyword}"
            )

    def test_allows_column_names_containing_keywords(self):
        """Words like 'updated_at', 'created_at', 'deleted' should not trigger."""
        assert WRITE_PATTERN.search("SELECT updated_at FROM users") is None
        assert WRITE_PATTERN.search("SELECT created_at FROM users") is None
        assert WRITE_PATTERN.search("SELECT deleted FROM users") is None


class TestResultFormatting:
    def test_markdown_table_format(self):
        result = _format_results(
            columns=["id", "email"],
            rows=[[1, "j***@e***.com"], [2, "j***@t***.org"]],
            annotations={"email": "[MASKED: EMAIL_ADDRESS]"},
            max_rows=1000,
        )
        assert "PII masked: email" in result
        assert "2 rows" in result
        assert "| id" in result
        assert "| 1" in result
        assert "j***@e***.com" in result

    def test_tsv_for_wide_results(self):
        """Results with >8 columns should use TSV format."""
        cols = [f"col{i}" for i in range(10)]
        rows = [[i for i in range(10)]]
        result = _format_results(cols, rows, {}, max_rows=1000)
        # TSV uses tabs, not pipes
        assert "\t" in result
        assert "|" not in result.split("\n")[-1]

    def test_truncation_indicator(self):
        result = _format_results(
            columns=["id"],
            rows=[[1], [2], [3]],
            annotations={},
            max_rows=3,
        )
        assert "truncated" in result

    def test_no_truncation_indicator(self):
        result = _format_results(
            columns=["id"],
            rows=[[1], [2]],
            annotations={},
            max_rows=1000,
        )
        assert "truncated" not in result

    def test_null_values(self):
        result = _format_results(
            columns=["id", "name"],
            rows=[[1, None]],
            annotations={},
            max_rows=1000,
        )
        assert "NULL" in result

    def test_revealed_columns_shown(self):
        result = _format_results(
            columns=["email"],
            rows=[["john@example.com"]],
            annotations={"email": "[UNMASKED]"},
            max_rows=1000,
        )
        assert "Revealed: email" in result
