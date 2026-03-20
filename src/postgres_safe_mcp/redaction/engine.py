"""Redaction engine — orchestrates PII detection and masking of query results."""

from __future__ import annotations

import json
import re
from typing import Any

from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from .detector import PiiDetector, PiiColumnInfo
from .maskers import mask_value, ALL_CUSTOM_OPERATORS

# Cheap pre-filter applied to JSON string values before invoking Presidio NER.
# A positive match triggers the expensive scan; a miss skips it entirely.
# Intentionally broad — false positives waste a NER call, false negatives leak PII.
_PII_PREFILTER = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"  # email
    r"|\b\d{3}[\s.\-]\d{3}[\s.\-]\d{4}\b"                  # phone NXX-NXX-XXXX
    r"|\(\d{3}\)\s*\d{3}[\s.\-]\d{4}"                       # phone (NXX) NXX-XXXX
    r"|\b\d{3}-\d{2}-\d{4}\b"                               # SSN
    r"|\b(?:\d{4}[\s\-]?){3}\d{4}\b",                       # credit card 16-digit
)


class RedactionEngine:
    """Orchestrates PII detection and masking of query results."""

    def __init__(
        self,
        detector: PiiDetector,
        default_masking_style: str = "partial",
        pseudo_seed: str = "postgres-safe-mcp",
    ) -> None:
        self._detector = detector
        self._default_masking_style = default_masking_style
        self._pseudo_seed = pseudo_seed
        # Style overrides per table.column
        self._style_overrides: dict[str, str] = {}
        # Lazy-initialized for free text columns
        self._anonymizer: AnonymizerEngine | None = None
        self._analyzer: AnalyzerEngine | None = None

    def _get_anonymizer(self) -> AnonymizerEngine:
        if self._anonymizer is None:
            self._anonymizer = AnonymizerEngine()
            for op_class in ALL_CUSTOM_OPERATORS:
                self._anonymizer.add_anonymizer(op_class)
        return self._anonymizer

    def _get_analyzer(self) -> AnalyzerEngine:
        if self._analyzer is None:
            self._analyzer = AnalyzerEngine()
        return self._analyzer

    def set_column_style(
        self, table_key: str, column: str, masking_style: str
    ) -> None:
        """Override the masking style for a specific column."""
        self._style_overrides[f"{table_key}.{column}"] = masking_style

    def get_masking_style(self, table_key: str, column: str) -> str:
        """Get the effective masking style for a column."""
        return self._style_overrides.get(
            f"{table_key}.{column}", self._default_masking_style
        )

    def redact_results(
        self,
        columns: list[str],
        rows: list[list[Any]],
        table_hints: list[str] | None = None,
        reveal_columns: list[str] | None = None,
        reveal_types: list[str] | None = None,
    ) -> tuple[list[list[Any]], dict[str, str]]:
        """Redact PII in query results.

        Returns:
            (redacted_rows, annotations) where annotations maps column names
            to status strings like "[UNMASKED]" or "[MASKED: EMAIL_ADDRESS]".
        """
        reveal_columns = reveal_columns or []
        reveal_types = reveal_types or []
        table_hints = table_hints or []

        # Build per-column redaction plan
        column_plan: list[_ColumnPlan | None] = []
        annotations: dict[str, str] = {}

        for col in columns:
            info = self._lookup_column(col, table_hints)
            if info is None:
                column_plan.append(None)
                continue

            # SECRET type can never be revealed
            if info.entity_type == "SECRET":
                style = "full"
                column_plan.append(
                    _ColumnPlan(info=info, style=style, revealed=False)
                )
                annotations[col] = "[MASKED: SECRET]"
                continue

            # Check if this column is revealed
            revealed = col in reveal_columns or info.entity_type in reveal_types
            if revealed:
                column_plan.append(
                    _ColumnPlan(info=info, style="none", revealed=True)
                )
                annotations[col] = "[UNMASKED]"
                continue

            # Normal masking — use first matching table hint for style lookup
            style = self.get_masking_style(
                table_hints[0] if table_hints else "", col
            )
            column_plan.append(
                _ColumnPlan(info=info, style=style, revealed=False)
            )
            annotations[col] = f"[MASKED: {info.entity_type}]"

        # Apply masking
        redacted = []
        for row in rows:
            new_row = []
            for i, value in enumerate(row):
                plan = column_plan[i] if i < len(column_plan) else None
                if plan is None or plan.revealed or plan.style == "none":
                    new_row.append(value)
                elif plan.info.is_json:
                    new_row.append(
                        self._mask_json_column_value(value, reveal_types, plan.style)
                    )
                elif plan.info.is_free_text:
                    new_row.append(
                        self._mask_free_text(value, reveal_types, plan.style)
                    )
                else:
                    new_row.append(
                        mask_value(
                            value,
                            plan.info.entity_type,
                            plan.style,
                            self._pseudo_seed,
                        )
                    )
            redacted.append(new_row)

        return redacted, annotations

    def _lookup_column(
        self, column: str, table_hints: list[str]
    ) -> PiiColumnInfo | None:
        """Look up PII info for a column.

        Tries each table hint in order (matching the FROM/JOIN appearance order),
        then falls back to bare column name heuristics.
        """
        for hint in table_hints:
            info = self._detector.get_cached_info(hint, column)
            if info is not None:
                return info
        # Fall back to name-only heuristics (works for descriptive names like
        # "email", "first_name" but not for generic names like "data")
        return self._detector.detect_column_pii(column)

    def _mask_json_column_value(
        self,
        value: Any,
        reveal_types: list[str],
        masking_style: str,
    ) -> Any:
        """Entry point for masking a JSON/JSONB column value.

        Handles the case where psycopg didn't deserialize the column (returns
        a raw string) by parsing it manually and re-serializing after masking.
        """
        if value is None:
            return None
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except (ValueError, TypeError):
                # Not valid JSON — fall back to free-text scanning
                return self._mask_free_text(value, reveal_types, masking_style)
            masked = self._mask_json_value(parsed, reveal_types, masking_style)
            return json.dumps(masked)
        return self._mask_json_value(value, reveal_types, masking_style)

    def _mask_json_value(
        self,
        value: Any,
        reveal_types: list[str],
        masking_style: str,
        _depth: int = 0,
    ) -> Any:
        """Recursively mask PII in a parsed JSON value.

        Handles dicts, lists, and scalar string leaves. Numbers, booleans,
        and None are returned as-is — they cannot contain PII.
        """
        if _depth > 15:
            return value
        if isinstance(value, dict):
            return {
                k: self._mask_json_field(k, v, reveal_types, masking_style, _depth + 1)
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [
                self._mask_json_value(v, reveal_types, masking_style, _depth + 1)
                for v in value
            ]
        if isinstance(value, str):
            # String with no key context (e.g. bare array element)
            if _PII_PREFILTER.search(value):
                return self._mask_free_text(value, reveal_types, masking_style)
            return value
        # int, float, bool, None — not PII
        return value

    def _mask_json_field(
        self,
        key: str,
        value: Any,
        reveal_types: list[str],
        masking_style: str,
        _depth: int,
    ) -> Any:
        """Mask a single JSON field, using the key name as a PII hint."""
        if not isinstance(value, str):
            # Non-string: recurse into nested objects/arrays; pass through scalars
            return self._mask_json_value(value, reveal_types, masking_style, _depth)

        # Fast path: key name matches a known PII pattern
        entity_type = self._detector.classify_json_key(key)
        if entity_type:
            # Secrets are always masked; other types respect reveal_types
            if entity_type == "SECRET" or entity_type not in reveal_types:
                return mask_value(value, entity_type, masking_style, self._pseudo_seed)
            return value  # explicitly revealed

        # Slow path: key name is neutral — check value with regex, then NER
        if _PII_PREFILTER.search(value):
            return self._mask_free_text(value, reveal_types, masking_style)
        return value

    def _mask_free_text(
        self,
        value: Any,
        reveal_types: list[str],
        masking_style: str,
    ) -> Any:
        """Mask PII embedded in free text using Presidio value-level analysis."""
        if value is None:
            return None

        text = str(value)
        if not text.strip():
            return value

        results = self._get_analyzer().analyze(text=text, language="en")
        if not results:
            return value

        # Filter out revealed types
        results = [r for r in results if r.entity_type not in reveal_types]
        if not results:
            return value

        # Build operator config based on masking style
        operators: dict[str, OperatorConfig] = {}
        for r in results:
            if r.entity_type not in operators:
                operators[r.entity_type] = _free_text_operator(
                    r.entity_type, masking_style
                )

        anonymized = self._get_anonymizer().anonymize(
            text=text,
            analyzer_results=results,
            operators=operators,
        )
        return anonymized.text


class _ColumnPlan:
    """Internal plan for how to handle a column during redaction."""

    __slots__ = ("info", "style", "revealed")

    def __init__(
        self, info: PiiColumnInfo, style: str, revealed: bool
    ) -> None:
        self.info = info
        self.style = style
        self.revealed = revealed


def _free_text_operator(entity_type: str, masking_style: str) -> OperatorConfig:
    """Get operator config for masking PII found in free text."""
    match masking_style:
        case "full":
            label = entity_type.replace("_", " ").upper()
            return OperatorConfig("replace", {"new_value": f"[{label}]"})
        case "pseudonymize":
            return OperatorConfig(
                "pseudonymize",
                {"seed": "postgres-safe-mcp", "entity_type": entity_type},
            )
        case _:  # "partial"
            # For free text, use replace with a hint since partial masking
            # on inline text is harder to do cleanly
            label = entity_type.replace("_", " ").upper()
            return OperatorConfig("replace", {"new_value": f"[{label}]"})
