# postgres-safe-mcp

A PostgreSQL MCP server that automatically detects and obfuscates PII in query results before they reach the AI. Connect Claude (or any MCP client) to your database without exposing sensitive data.

## How it works

1. **Connect** — Point the server at any PostgreSQL database (local or remote)
2. **Auto-detect** — On first query, the server scans column names and samples data to classify which columns contain PII (emails, names, phones, SSNs, etc.)
3. **Mask by default** — Query results are automatically masked before the AI sees them:
   ```
   SELECT * FROM users LIMIT 2;

   PII masking applied: email [MASKED: EMAIL_ADDRESS], first_name [MASKED: PERSON], phone [MASKED: PHONE_NUMBER]
   Rows: 2
   [
     {"id": 1, "email": "j***@e***.com", "first_name": "J***", "phone": "***-***-4567"},
     {"id": 2, "email": "j***@t***.org", "first_name": "J***", "phone": "***-***-8901"}
   ]
   ```
4. **Reveal when needed** — When the AI needs real data to solve a problem, it can request specific columns or PII types to be unmasked:
   ```
   query(sql="SELECT * FROM users", reveal_columns=["email"])
   ```
   The human approves each tool call in Claude Code, so you always see what's being revealed.

## PII detection

Detection uses a two-layer approach:

- **Column name heuristics** (fast, no NLP) — Pattern matching on column names handles common patterns like `email`, `first_name`, `phone`, plus prefixed variants like `bus_email`, `rep_phone_number`, `pref_first_name`, `former_last_name`
- **Presidio NLP analysis** (on first access) — Samples ~100 rows and runs Microsoft Presidio to detect PII in column values, catching columns with non-obvious names

Detected PII types include: email addresses, phone numbers, names, physical addresses, SSNs, tax IDs, credit cards, IP addresses, dates of birth, financial account numbers, geolocation, and more.

**Secret columns** (encrypted passwords, tokens, OTP secrets) are always fully redacted and cannot be revealed.

**Free text columns** (message bodies, notes, descriptions) get value-level Presidio scanning since PII is embedded in prose.

## Masking styles

| Style | Example | Description |
|---|---|---|
| `partial` (default) | `j***@e***.com` | Shows enough structure to be useful, hides the sensitive parts |
| `full` | `[EMAIL ADDRESS]` | Complete replacement with a type label |
| `pseudonymize` | `user_a3f2@masked.invalid` | Deterministic fake values — same input always produces the same output, preserving relationships across queries |
| `none` | `john@example.com` | No masking (for columns you've explicitly marked as safe) |

## Installation

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone <repo-url>
cd postgres-safe-mcp
uv sync
```

On first run, the spaCy NLP model (`en_core_web_lg`, ~560MB) will be downloaded automatically.

## Usage

### With Claude Code

Add to your `.mcp.json` (project-level or `~/.claude/.mcp.json` for global):

```json
{
  "mcpServers": {
    "postgres-safe": {
      "command": "uv",
      "args": [
        "run",
        "--directory", "/path/to/postgres-safe-mcp",
        "python", "-m", "postgres_safe_mcp",
        "-c", "postgresql://user:pass@localhost:5432/mydb"
      ]
    }
  }
}
```

### With a config file

```bash
uv run python -m postgres_safe_mcp --config config.yaml
```

### CLI options

| Flag | Description |
|---|---|
| `-c`, `--connection-string` | PostgreSQL connection string (highest priority) |
| `--config` | Path to YAML config file |

Connection string precedence: CLI arg > `DATABASE_URL` env var > config file.

## MCP Tools

### `query`
Execute a read-only SQL query with automatic PII redaction.

| Parameter | Type | Description |
|---|---|---|
| `sql` | string | SQL query (read-only, SELECT only) |
| `params` | dict | Query parameters for parameterized queries |
| `reveal_columns` | list[string] | Column names to show unmasked |
| `reveal_types` | list[string] | PII entity types to show unmasked (e.g. `EMAIL_ADDRESS`, `PERSON`) |

### `describe_schema`
List tables and columns with their types and PII detection status.

| Parameter | Type | Description |
|---|---|---|
| `table` | string | Table name (omit for all tables) |
| `show_pii` | bool | Show PII detection status (default: true) |

### `explain_query`
Show the PostgreSQL execution plan for a query.

### `configure_masking`
Override masking rules at runtime (in-memory, not persisted).

| Parameter | Type | Description |
|---|---|---|
| `table` | string | Table name |
| `column` | string | Column name |
| `masking_style` | string | `partial`, `full`, `pseudonymize`, or `none` |
| `pii_type` | string | PII entity type override |

### `list_masking_rules`
Show all active PII classifications and masking rules.

## Configuration

See [`config.example.yaml`](config.example.yaml) for a full example.

```yaml
connection_string: "postgresql://user:pass@localhost:5432/mydb"
default_masking_style: "partial"
auto_detect: true
sample_size: 100
max_rows: 1000
allowed_schemas:
  - public

# Manual overrides take precedence over auto-detection
column_rules:
  - table: users
    column: email
    pii_type: EMAIL_ADDRESS
    masking_style: partial
  - table: users
    column: internal_id
    pii_type: none          # explicitly mark as NOT PII
    masking_style: none
```

## Development

```bash
# Install with dev dependencies
uv sync --all-extras

# Run tests
uv run pytest

# Run tests with verbose output
uv run pytest -v
```
