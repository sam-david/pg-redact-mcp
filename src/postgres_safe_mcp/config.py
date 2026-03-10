"""Configuration loading and validation."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class ColumnMaskingRule:
    """Manual masking override for a specific column."""

    table: str
    column: str
    pii_type: str  # e.g. "EMAIL_ADDRESS", "PERSON", "none"
    masking_style: str = "partial"  # partial | full | pseudonymize | none


@dataclass
class Config:
    """Server configuration."""

    connection_string: str = ""
    default_masking_style: str = "partial"
    sample_size: int = 100
    auto_detect: bool = True
    read_only: bool = True
    column_rules: list[ColumnMaskingRule] = field(default_factory=list)
    allowed_schemas: list[str] = field(default_factory=lambda: ["public"])
    max_rows: int = 1000

    def get_column_rule(self, table: str, column: str) -> ColumnMaskingRule | None:
        """Look up a manual override for a specific table.column."""
        for rule in self.column_rules:
            if rule.table == table and rule.column == column:
                return rule
        return None


def load_config(
    config_path: str | None = None,
    connection_string: str | None = None,
    read_only: bool | None = None,
) -> Config:
    """Load config with precedence: CLI args > env vars > config file > defaults."""
    config = Config()

    # Load from YAML file if provided
    if config_path:
        path = Path(config_path)
        if path.exists():
            with open(path) as f:
                data = yaml.safe_load(f) or {}
            _apply_yaml(config, data)

    # Env var overrides config file
    env_conn = os.environ.get("DATABASE_URL")
    if env_conn:
        config.connection_string = env_conn

    # CLI args override everything
    if connection_string:
        config.connection_string = connection_string
    if read_only is not None:
        config.read_only = read_only

    return config


def _apply_yaml(config: Config, data: dict) -> None:
    """Apply YAML data to config object."""
    if "connection_string" in data:
        config.connection_string = data["connection_string"]
    if "default_masking_style" in data:
        config.default_masking_style = data["default_masking_style"]
    if "sample_size" in data:
        config.sample_size = data["sample_size"]
    if "auto_detect" in data:
        config.auto_detect = data["auto_detect"]
    if "read_only" in data:
        config.read_only = data["read_only"]
    if "allowed_schemas" in data:
        config.allowed_schemas = data["allowed_schemas"]
    if "max_rows" in data:
        config.max_rows = data["max_rows"]
    if "column_rules" in data:
        config.column_rules = [
            ColumnMaskingRule(**rule) for rule in data["column_rules"]
        ]
