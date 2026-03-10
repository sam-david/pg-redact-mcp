"""Tests for the MCP server tool handlers."""

import re

from postgres_safe_mcp.server import WRITE_PATTERN


class TestWritePatternValidation:
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
