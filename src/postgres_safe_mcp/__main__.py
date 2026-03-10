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
        subprocess.check_call(
            [sys.executable, "-m", "spacy", "download", "en_core_web_lg"],
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
    args = parser.parse_args()

    ensure_spacy_model()

    config = load_config(
        config_path=args.config,
        connection_string=args.connection_string,
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
