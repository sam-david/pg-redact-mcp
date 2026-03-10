# postgres-safe-mcp

A PostgreSQL MCP server that automatically detects and obfuscates PII in query results before they reach the AI. Connect Claude (or any MCP client) to your database without exposing sensitive data.

## How it works

1. **Connect** — Point the server at any PostgreSQL database (local or remote)
2. **Schema check** — The agent calls `describe_schema` first to learn the actual table and column names, avoiding guesswork and failed queries
3. **Auto-detect** — On startup, the server runs instant heuristic detection on all column names to classify PII (emails, names, phones, SSNs, etc.). No data sampling required — column name patterns catch the vast majority of PII fields
4. **Mask by default** — Query results are automatically masked before the AI sees them:
   ```
   PII masked: first_name (MASKED: PERSON), last_name (MASKED: PERSON), email (MASKED: EMAIL_ADDRESS)
   3 rows

   | id   | first_name | last_name | email         | created_at |
   |------|------------|-----------|---------------|------------|
   | 5022 | S**        | D****     | s***@g***.com | 2026-03-06 |
   | 5021 | S**        | D****     | s***@g***.com | 2026-03-03 |
   | 5020 | l***       | c***      | l***@t***.com | 2026-02-24 |
   ```
5. **Reveal when needed** — The AI can selectively unmask specific columns or PII types when the user explicitly asks to see real data

## Masking and unmasking

### Default behavior: everything masked

Every query runs through the redaction engine before results reach the AI. PII columns are detected by name pattern and masked automatically. The AI sees partial values like `J******` instead of `Jessica` — enough structure to reason about the data without exposing real PII.

### How the AI decides what to reveal

The `query` tool accepts two optional parameters for selective unmasking:

- **`reveal_columns`** — Unmask specific columns by name (e.g. `["email", "first_name"]`)
- **`reveal_types`** — Unmask all columns of a PII type (e.g. `["EMAIL_ADDRESS"]`)

The AI is guided by these rules in the tool description:

| Scenario | What the AI does |
|---|---|
| "Show me the last 5 registrations" | Keeps everything masked — browsing doesn't need real data |
| "How many users signed up last month?" | Aggregate query, no PII in results |
| "What is the email for registration 5015?" | Reveals `email` — user explicitly asked for it |
| "Show me John's full name" | Reveals `first_name`, `last_name` — user asked to see the value |
| "Are there duplicate registrations?" | Keeps masked — duplicates are detectable from masked patterns |

### Secret columns can never be revealed

Columns matching patterns like `encrypted_password`, `otp_secret_key`, `reset_password_token` are classified as `SECRET`. These are always fully redacted (`[REDACTED]`) and **cannot be unmasked** even if `reveal_columns` or `reveal_types` is used. There's no legitimate reason for an AI agent to see raw password hashes or auth tokens.

### Manual overrides

You can force specific masking behavior per column in your config:

```yaml
column_rules:
  # Force a column to be treated as PII even if the name doesn't match patterns
  - table: users
    column: custom_id_field
    pii_type: US_SSN
    masking_style: partial

  # Explicitly mark a column as NOT PII (skip masking)
  - table: users
    column: display_name    # public-facing, not sensitive
    pii_type: none
    masking_style: none
```

Or at runtime via the `configure_masking` tool (in-memory, not persisted).

### Human in the loop

In Claude Code, every tool call is shown to the user before execution. When the AI uses `reveal_columns`, you see exactly which columns are being unmasked and can approve or deny the request. This creates a natural checkpoint — the AI proposes what to reveal, you decide whether to allow it.

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
| `--read-only` | Only allow SELECT queries (default) |
| `--read-write` | Allow INSERT, UPDATE, DELETE, and other write queries |

Connection string precedence: CLI arg > `DATABASE_URL` env var > config file.
Read-only precedence: CLI flag > config file > default (true).

## MCP Tools

### `query`
Execute a SQL query with automatic PII redaction. Write queries (INSERT, UPDATE, DELETE) are blocked in read-only mode (default) and allowed when configured with `read_only: false`.

| Parameter | Type | Description |
|---|---|---|
| `sql` | string | SQL query (write queries require read-only mode to be disabled) |
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
read_only: true                     # false to allow INSERT/UPDATE/DELETE
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
