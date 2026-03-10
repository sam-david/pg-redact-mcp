"""Tests for configuration loading."""

import os
import tempfile
from pathlib import Path

import yaml

from postgres_safe_mcp.config import Config, ColumnMaskingRule, load_config


class TestConfigDefaults:
    def test_default_values(self):
        config = Config()
        assert config.default_masking_style == "partial"
        assert config.sample_size == 100
        assert config.auto_detect is True
        assert config.allowed_schemas == ["public"]
        assert config.max_rows == 1000
        assert config.column_rules == []

    def test_get_column_rule_found(self):
        rule = ColumnMaskingRule(
            table="users", column="email", pii_type="EMAIL_ADDRESS"
        )
        config = Config(column_rules=[rule])
        assert config.get_column_rule("users", "email") == rule

    def test_get_column_rule_not_found(self):
        config = Config()
        assert config.get_column_rule("users", "email") is None


class TestLoadConfig:
    def test_load_from_yaml(self):
        data = {
            "connection_string": "postgresql://test@localhost/testdb",
            "default_masking_style": "full",
            "sample_size": 50,
            "auto_detect": False,
            "max_rows": 500,
            "allowed_schemas": ["public", "analytics"],
            "column_rules": [
                {
                    "table": "users",
                    "column": "email",
                    "pii_type": "EMAIL_ADDRESS",
                    "masking_style": "partial",
                }
            ],
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(data, f)
            f.flush()
            config = load_config(config_path=f.name)

        os.unlink(f.name)

        assert config.connection_string == "postgresql://test@localhost/testdb"
        assert config.default_masking_style == "full"
        assert config.sample_size == 50
        assert config.auto_detect is False
        assert config.max_rows == 500
        assert config.allowed_schemas == ["public", "analytics"]
        assert len(config.column_rules) == 1
        assert config.column_rules[0].table == "users"

    def test_cli_arg_overrides_config_file(self):
        data = {"connection_string": "postgresql://from-file@localhost/db"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(data, f)
            f.flush()
            config = load_config(
                config_path=f.name,
                connection_string="postgresql://from-cli@localhost/db",
            )

        os.unlink(f.name)
        assert config.connection_string == "postgresql://from-cli@localhost/db"

    def test_env_var_overrides_config_file(self, monkeypatch):
        data = {"connection_string": "postgresql://from-file@localhost/db"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(data, f)
            f.flush()
            monkeypatch.setenv("DATABASE_URL", "postgresql://from-env@localhost/db")
            config = load_config(config_path=f.name)

        os.unlink(f.name)
        assert config.connection_string == "postgresql://from-env@localhost/db"

    def test_cli_overrides_env_var(self, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", "postgresql://from-env@localhost/db")
        config = load_config(
            connection_string="postgresql://from-cli@localhost/db"
        )
        assert config.connection_string == "postgresql://from-cli@localhost/db"

    def test_missing_config_file_uses_defaults(self):
        config = load_config(config_path="/nonexistent/path.yaml")
        assert config.default_masking_style == "partial"

    def test_empty_yaml(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("")
            f.flush()
            config = load_config(config_path=f.name)
        os.unlink(f.name)
        assert config.default_masking_style == "partial"
