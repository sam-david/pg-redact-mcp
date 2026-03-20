"""PII detection via column name heuristics and Presidio analysis."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Callable, Awaitable

from presidio_analyzer import AnalyzerEngine


@dataclass
class PiiColumnInfo:
    """PII classification for a single column."""

    entity_type: str  # e.g. "EMAIL_ADDRESS", "PERSON", "SECRET"
    confidence: float  # 0.0 - 1.0
    source: str  # "heuristic", "presidio", "manual"
    is_free_text: bool = False  # needs value-level scanning
    is_json: bool = False  # JSON/JSONB column — recurse into structure


# Column name patterns → PII entity type (substring matching)
COLUMN_NAME_HINTS: dict[str, str] = {
    # Email
    r"e?mail": "EMAIL_ADDRESS",
    # Phone
    r"phone|mobile|cell\b|fax": "PHONE_NUMBER",
    # SSN / Tax IDs
    r"ssn|social_security|tax_?id|\bein\b|\bcpf\b": "US_SSN",
    # Names — with common prefixes
    r"(first|last|full|middle|maiden|former|spouse|pref)[_.]?name|nickname|holder_name|payer_name|paid_name": "PERSON",
    # IP addresses (must come before general "address" pattern)
    r"ip_?addr|remote_addr|sign_in_ip": "IP_ADDRESS",
    # Geolocation
    r"\blat\b|\blon\b|latitude|longitude": "LOCATION",
    # Addresses
    r"address|street|city\b|state\b|zip|postal|country\b": "LOCATION",
    # DOB
    r"date_of_birth|dob|birth_?date": "DATE_TIME",
    # Credit cards
    r"credit_?card|card_?number|\bpan\b": "CREDIT_CARD",
    # Financial
    r"routing_?number|bank_?account|account_?number": "FINANCIAL",
    # Encrypted/secrets — always redact, never reveal
    r"encrypted_|otp_secret|reset_password_token|confirmation_token|unlock_token": "SECRET",
    # Government IDs
    r"passport|driver.?license|dl_?num": "US_PASSPORT",
}

# Columns that need value-level Presidio scanning (free text)
FREE_TEXT_HINTS: list[str] = [
    r"message|body|content|description|notes|comment|narrative|substitution|metadata|changes",
]


class PiiDetector:
    """Detects PII in database columns using heuristics and Presidio."""

    def __init__(self, analyzer: AnalyzerEngine | None = None) -> None:
        self._analyzer = analyzer
        self._analyzer_initialized = analyzer is not None
        self._cache: dict[str, PiiColumnInfo | None] = {}

    def _get_analyzer(self) -> AnalyzerEngine:
        """Lazy-initialize the Presidio analyzer."""
        if not self._analyzer_initialized:
            self._analyzer = AnalyzerEngine()
            self._analyzer_initialized = True
        assert self._analyzer is not None
        return self._analyzer

    def detect_column_pii(
        self,
        column_name: str,
        sample_values: list[str] | None = None,
    ) -> PiiColumnInfo | None:
        """Detect PII type for a column using name heuristics, then Presidio on samples."""
        # Check free text first
        for pattern in FREE_TEXT_HINTS:
            if re.search(pattern, column_name, re.IGNORECASE):
                return PiiColumnInfo(
                    entity_type="FREE_TEXT",
                    confidence=0.8,
                    source="heuristic",
                    is_free_text=True,
                )

        # Column name heuristics (fast path)
        for pattern, entity_type in COLUMN_NAME_HINTS.items():
            if re.search(pattern, column_name, re.IGNORECASE):
                return PiiColumnInfo(
                    entity_type=entity_type,
                    confidence=0.9,
                    source="heuristic",
                )

        # Presidio analysis on sample values (slow path, requires NLP model)
        if sample_values and self._analyzer_initialized:
            return self._analyze_samples(sample_values)

        return None

    def _analyze_samples(self, samples: list[str]) -> PiiColumnInfo | None:
        """Run Presidio analyzer on sample values and vote on entity type."""
        votes: Counter[str] = Counter()
        total_scores: dict[str, float] = {}

        for value in samples:
            if not value or not value.strip():
                continue
            results = self._get_analyzer().analyze(text=value, language="en")
            for result in results:
                votes[result.entity_type] += 1
                total_scores[result.entity_type] = (
                    total_scores.get(result.entity_type, 0.0) + result.score
                )

        if not votes:
            return None

        # Pick the most common entity type
        top_entity, count = votes.most_common(1)[0]
        # Require at least 20% of samples to match
        if count < len(samples) * 0.2:
            return None

        avg_score = total_scores[top_entity] / count
        return PiiColumnInfo(
            entity_type=top_entity,
            confidence=avg_score,
            source="presidio",
        )

    async def scan_table(
        self,
        table_key: str,
        columns: list[str],
        sampler: Callable[[str], Awaitable[list[str]]],
    ) -> dict[str, PiiColumnInfo]:
        """Scan all columns in a table, using cache."""
        results: dict[str, PiiColumnInfo] = {}
        for col in columns:
            cache_key = f"{table_key}.{col}"
            if cache_key in self._cache:
                if self._cache[cache_key] is not None:
                    results[col] = self._cache[cache_key]  # type: ignore[assignment]
                continue

            samples = await sampler(col)
            info = self.detect_column_pii(col, samples)
            self._cache[cache_key] = info
            if info is not None:
                results[col] = info

        return results

    def set_manual_override(
        self,
        table_key: str,
        column: str,
        entity_type: str,
        masking_style: str = "partial",
    ) -> None:
        """Set a manual PII classification override."""
        cache_key = f"{table_key}.{column}"
        if entity_type == "none":
            self._cache[cache_key] = None
        else:
            self._cache[cache_key] = PiiColumnInfo(
                entity_type=entity_type,
                confidence=1.0,
                source="manual",
            )

    def classify_json_key(self, key_name: str) -> str | None:
        """Classify a JSON object key using column name heuristics.

        Like detect_column_pii but: no caching, no free-text check, no sampling.
        Used for fast key-name matching inside JSON blobs.
        """
        for pattern, entity_type in COLUMN_NAME_HINTS.items():
            if re.search(pattern, key_name, re.IGNORECASE):
                return entity_type
        return None

    def get_cached_info(self, table_key: str, column: str) -> PiiColumnInfo | None:
        """Look up cached PII info for a column."""
        return self._cache.get(f"{table_key}.{column}")

    def get_all_cached(self) -> dict[str, PiiColumnInfo | None]:
        """Return the full cache for reporting."""
        return dict(self._cache)
