"""CLI entry point for postgres-safe-mcp."""

import argparse
import subprocess
import sys

from .config import load_config
from .server import create_server


def ensure_spacy_model() -> None:
    """Download spaCy model if not already installed."""
    try:
        import spacy
        spacy.load("en_core_web_lg")
    except OSError:
        print("Downloading spaCy model en_core_web_lg (first run only)...", file=sys.stderr)
        # Use uv pip instead of pip directly, since uv-managed venvs
        # don't include pip by default
        subprocess.check_call(
            ["uv", "pip", "install", "en-core-web-lg",
             "--find-links", "https://github.com/explosion/spacy-models/releases/expanded_assets/en_core_web_lg-3.8.0"],
            stdout=sys.stderr,
            stderr=sys.stderr,
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PostgreSQL MCP server with PII redaction"
    )
    parser.add_argument(
        "-c", "--connection-string",
        help="PostgreSQL connection string (overrides config file and DATABASE_URL)",
    )
    parser.add_argument(
        "--config",
        help="Path to YAML config file",
    )
    read_only_group = parser.add_mutually_exclusive_group()
    read_only_group.add_argument(
        "--read-only",
        action="store_true",
        default=None,
        help="Only allow SELECT queries (default)",
    )
    read_only_group.add_argument(
        "--read-write",
        action="store_true",
        default=None,
        help="Allow INSERT, UPDATE, DELETE, and other write queries",
    )
    args = parser.parse_args()

    ensure_spacy_model()

    # Determine read_only override from CLI flags
    read_only_override = None
    if args.read_only:
        read_only_override = True
    elif args.read_write:
        read_only_override = False

    config = load_config(
        config_path=args.config,
        connection_string=args.connection_string,
        read_only=read_only_override,
    )

    if not config.connection_string:
        print(
            "Error: No connection string provided. Use --connection-string, "
            "DATABASE_URL env var, or a config file.",
            file=sys.stderr,
        )
        sys.exit(1)

    server = create_server(config)
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
