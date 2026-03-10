"""Tests for the redaction engine."""

from postgres_safe_mcp.redaction.detector import PiiDetector, PiiColumnInfo
from postgres_safe_mcp.redaction.engine import RedactionEngine


def _make_engine(cached: dict[str, PiiColumnInfo | None] | None = None) -> RedactionEngine:
    """Create an engine with pre-cached PII info (no Presidio needed)."""
    detector = PiiDetector(analyzer=None)
    if cached:
        for key, info in cached.items():
            detector._cache[key] = info
    return RedactionEngine(detector=detector)


class TestRedactResults:
    def test_no_pii_columns(self):
        engine = _make_engine()
        columns = ["id", "amount", "status"]
        rows = [[1, 100.0, "active"], [2, 200.0, "inactive"]]
        redacted, annotations = engine.redact_results(columns, rows)
        assert redacted == rows
        assert annotations == {}

    def test_masks_email_column(self):
        engine = _make_engine()
        # "email" triggers heuristic detection
        columns = ["id", "email"]
        rows = [[1, "john@example.com"], [2, "jane@test.org"]]
        redacted, annotations = engine.redact_results(columns, rows)
        assert redacted[0][0] == 1  # id unchanged
        assert redacted[0][1] == "j***@e***.com"
        assert redacted[1][1] == "j***@t***.org"
        assert "MASKED" in annotations["email"]

    def test_masks_phone_column(self):
        engine = _make_engine()
        columns = ["phone"]
        rows = [["555-123-4567"]]
        redacted, _ = engine.redact_results(columns, rows)
        assert redacted[0][0] == "***-***-4567"

    def test_masks_secret_column(self):
        engine = _make_engine()
        columns = ["encrypted_password"]
        rows = [["$2a$10$hashvalue"]]
        redacted, annotations = engine.redact_results(columns, rows)
        assert redacted[0][0] == "[REDACTED]"
        assert "SECRET" in annotations["encrypted_password"]

    def test_null_passthrough(self):
        engine = _make_engine()
        columns = ["email"]
        rows = [[None]]
        redacted, _ = engine.redact_results(columns, rows)
        assert redacted[0][0] is None

    def test_reveal_columns(self):
        engine = _make_engine()
        columns = ["id", "email", "phone"]
        rows = [[1, "john@example.com", "555-123-4567"]]
        redacted, annotations = engine.redact_results(
            columns, rows, reveal_columns=["email"]
        )
        assert redacted[0][1] == "john@example.com"  # revealed
        assert redacted[0][2] == "***-***-4567"  # still masked
        assert annotations["email"] == "[UNMASKED]"

    def test_reveal_types(self):
        engine = _make_engine()
        columns = ["email", "phone"]
        rows = [["john@example.com", "555-123-4567"]]
        redacted, annotations = engine.redact_results(
            columns, rows, reveal_types=["EMAIL_ADDRESS"]
        )
        assert redacted[0][0] == "john@example.com"  # revealed by type
        assert redacted[0][1] == "***-***-4567"  # still masked
        assert annotations["email"] == "[UNMASKED]"

    def test_secret_cannot_be_revealed_by_column(self):
        engine = _make_engine()
        columns = ["encrypted_password"]
        rows = [["$2a$10$hashvalue"]]
        redacted, annotations = engine.redact_results(
            columns, rows, reveal_columns=["encrypted_password"]
        )
        # SECRET is never revealed
        assert redacted[0][0] == "[REDACTED]"
        assert "SECRET" in annotations["encrypted_password"]

    def test_secret_cannot_be_revealed_by_type(self):
        engine = _make_engine()
        columns = ["encrypted_password"]
        rows = [["$2a$10$hashvalue"]]
        redacted, _ = engine.redact_results(
            columns, rows, reveal_types=["SECRET"]
        )
        assert redacted[0][0] == "[REDACTED]"

    def test_full_masking_style(self):
        engine = _make_engine()
        engine._default_masking_style = "full"
        columns = ["email"]
        rows = [["john@example.com"]]
        redacted, _ = engine.redact_results(columns, rows)
        assert redacted[0][0] == "[EMAIL ADDRESS]"

    def test_pseudonymize_style(self):
        engine = _make_engine()
        engine._default_masking_style = "pseudonymize"
        columns = ["email"]
        rows = [["john@example.com"]]
        redacted, _ = engine.redact_results(columns, rows)
        assert "@masked.invalid" in redacted[0][0]

    def test_pseudonymize_consistent(self):
        engine = _make_engine()
        engine._default_masking_style = "pseudonymize"
        columns = ["email"]
        rows = [["john@example.com"], ["john@example.com"]]
        redacted, _ = engine.redact_results(columns, rows)
        assert redacted[0][0] == redacted[1][0]

    def test_column_style_override(self):
        engine = _make_engine()
        engine.set_column_style("", "email", "full")
        columns = ["email"]
        rows = [["john@example.com"]]
        redacted, _ = engine.redact_results(columns, rows)
        assert redacted[0][0] == "[EMAIL ADDRESS]"

    def test_cached_pii_info_used(self):
        engine = _make_engine({
            "public.users.custom_field": PiiColumnInfo(
                entity_type="EMAIL_ADDRESS",
                confidence=1.0,
                source="manual",
            )
        })
        columns = ["custom_field"]
        rows = [["john@example.com"]]
        redacted, annotations = engine.redact_results(
            columns, rows, table_hint="public.users"
        )
        assert redacted[0][0] == "j***@e***.com"

    def test_multiple_pii_columns(self):
        engine = _make_engine()
        columns = ["first_name", "email", "phone", "id"]
        rows = [["John Doe", "john@example.com", "555-123-4567", 42]]
        redacted, annotations = engine.redact_results(columns, rows)
        assert redacted[0][0] == "J*** D**"
        assert redacted[0][1] == "j***@e***.com"
        assert redacted[0][2] == "***-***-4567"
        assert redacted[0][3] == 42  # not PII


class TestRevealInteractions:
    def test_reveal_column_and_type_together(self):
        engine = _make_engine()
        columns = ["email", "phone", "first_name"]
        rows = [["john@example.com", "555-123-4567", "John"]]
        redacted, annotations = engine.redact_results(
            columns,
            rows,
            reveal_columns=["email"],
            reveal_types=["PERSON"],
        )
        assert redacted[0][0] == "john@example.com"  # by column
        assert redacted[0][1] == "***-***-4567"  # still masked
        assert redacted[0][2] == "John"  # by type
        assert annotations["email"] == "[UNMASKED]"
        assert annotations["first_name"] == "[UNMASKED]"
