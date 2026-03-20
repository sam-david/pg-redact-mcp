"""Tests for the redaction engine."""

from postgres_safe_mcp.redaction.detector import PiiDetector, PiiColumnInfo
from postgres_safe_mcp.redaction.engine import RedactionEngine, _PII_PREFILTER


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
            columns, rows, table_hints=["public.users"]
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


def _make_json_engine() -> RedactionEngine:
    """Engine with a pre-cached JSON column (simulates schema detection)."""
    detector = PiiDetector(analyzer=None)
    detector._cache["public.users.data"] = PiiColumnInfo(
        entity_type="JSON_CONTAINER",
        confidence=1.0,
        source="heuristic",
        is_json=True,
    )
    return RedactionEngine(detector=detector)


class TestJsonMasking:
    """Tests for _mask_json_value and the JSON redaction path in redact_results."""

    def test_pii_prefilter_matches_email(self):
        assert _PII_PREFILTER.search("john@example.com")

    def test_pii_prefilter_matches_phone(self):
        assert _PII_PREFILTER.search("555-123-4567")
        assert _PII_PREFILTER.search("(555) 123-4567")

    def test_pii_prefilter_matches_ssn(self):
        assert _PII_PREFILTER.search("123-45-6789")

    def test_pii_prefilter_no_match_plain_text(self):
        assert not _PII_PREFILTER.search("active")
        assert not _PII_PREFILTER.search("confirmed")
        assert not _PII_PREFILTER.search("2024-01-01")

    def test_key_name_masking_email(self):
        engine = _make_json_engine()
        value = {"email": "john@example.com", "status": "active"}
        result = engine._mask_json_value(value, [], "partial")
        assert result["email"] == "j***@e***.com"
        assert result["status"] == "active"

    def test_key_name_masking_phone(self):
        engine = _make_json_engine()
        value = {"phone": "555-123-4567", "tier": "gold"}
        result = engine._mask_json_value(value, [], "partial")
        assert result["phone"] == "***-***-4567"
        assert result["tier"] == "gold"

    def test_key_name_masking_secret_always_redacted(self):
        engine = _make_json_engine()
        value = {"encrypted_password": "abc123", "name": "John"}
        result = engine._mask_json_value(value, ["SECRET"], "partial")
        assert result["encrypted_password"] == "[REDACTED]"

    def test_nested_object(self):
        engine = _make_json_engine()
        # "city" correctly triggers LOCATION masking; use a neutral key for the
        # passthrough assertion instead
        value = {"contact": {"email": "john@example.com", "tier": "gold"}}
        result = engine._mask_json_value(value, [], "partial")
        assert result["contact"]["email"] == "j***@e***.com"
        assert result["contact"]["tier"] == "gold"

    def test_array_of_objects(self):
        engine = _make_json_engine()
        value = [{"email": "a@b.com"}, {"email": "c@d.com"}]
        result = engine._mask_json_value(value, [], "partial")
        assert result[0]["email"] == "a***@b***.com"
        assert result[1]["email"] == "c***@d***.com"

    def test_array_of_strings_with_email(self):
        engine = _make_json_engine()
        value = ["hello", "john@example.com", "world"]
        result = engine._mask_json_value(value, [], "partial")
        assert result[0] == "hello"
        assert result[2] == "world"
        # The email string gets passed through Presidio NER via prefilter —
        # just assert it was changed (don't hardcode Presidio's output format)
        assert result[1] != "john@example.com"

    def test_non_string_scalars_passthrough(self):
        engine = _make_json_engine()
        value = {"count": 42, "active": True, "score": 3.14, "note": None}
        result = engine._mask_json_value(value, [], "partial")
        assert result == value

    def test_reveal_type_in_json(self):
        engine = _make_json_engine()
        value = {"email": "john@example.com", "phone": "555-123-4567"}
        result = engine._mask_json_value(value, ["EMAIL_ADDRESS"], "partial")
        assert result["email"] == "john@example.com"  # revealed
        assert result["phone"] == "***-***-4567"      # still masked

    def test_depth_limit(self):
        engine = _make_json_engine()
        # Build a deeply nested dict beyond the limit — should not crash
        deep: dict = {}
        node = deep
        for _ in range(20):
            node["child"] = {}
            node = node["child"]
        node["email"] = "john@example.com"
        # Should not raise; deep values beyond limit are returned as-is
        engine._mask_json_value(deep, [], "partial")

    def test_unparsed_json_string_column(self):
        """Handles columns where psycopg returns a raw JSON string instead of a dict."""
        engine = _make_json_engine()
        import json
        raw = json.dumps({"email": "john@example.com"})
        result = engine._mask_json_column_value(raw, [], "partial")
        parsed = json.loads(result)
        assert parsed["email"] == "j***@e***.com"

    def test_null_json_column(self):
        engine = _make_json_engine()
        assert engine._mask_json_column_value(None, [], "partial") is None

    def test_redact_results_json_column(self):
        engine = _make_json_engine()
        columns = ["id", "data"]
        rows = [[1, {"email": "john@example.com", "status": "active"}]]
        redacted, annotations = engine.redact_results(
            columns, rows, table_hints=["public.users"]
        )
        assert redacted[0][0] == 1
        assert redacted[0][1]["email"] == "j***@e***.com"
        assert redacted[0][1]["status"] == "active"
        assert "JSON_CONTAINER" in annotations["data"]

    def test_full_masking_style_on_json(self):
        engine = _make_json_engine()
        engine._default_masking_style = "full"
        value = {"email": "john@example.com"}
        result = engine._mask_json_value(value, [], "full")
        assert result["email"] == "[EMAIL ADDRESS]"

    def test_empty_json_object(self):
        engine = _make_json_engine()
        assert engine._mask_json_value({}, [], "partial") == {}

    def test_empty_json_array(self):
        engine = _make_json_engine()
        assert engine._mask_json_value([], [], "partial") == []
