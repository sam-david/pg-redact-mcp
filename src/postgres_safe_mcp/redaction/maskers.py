"""Masking strategies for different PII types."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from presidio_anonymizer.entities import OperatorConfig
from presidio_anonymizer.operators import Operator, OperatorType


# --- Custom partial masking operators ---


class PartialEmailMask(Operator):
    """john@example.com → j***@e***.com"""

    def operate(self, text: str, params: dict | None = None) -> str:
        if "@" not in text:
            return _generic_partial(text)
        local, domain = text.split("@", 1)
        parts = domain.rsplit(".", 1)
        masked_local = (local[0] + "***") if local else "***"
        masked_domain = (parts[0][0] + "***") if parts[0] else "***"
        tld = ("." + parts[1]) if len(parts) > 1 else ""
        return f"{masked_local}@{masked_domain}{tld}"

    def validate(self, params: dict | None = None) -> None:
        pass

    def operator_name(self) -> str:
        return "partial_email_mask"

    def operator_type(self) -> OperatorType:
        return OperatorType.Anonymize


class PartialPhoneMask(Operator):
    """555-123-4567 → ***-***-4567"""

    def operate(self, text: str, params: dict | None = None) -> str:
        digits = re.sub(r"\D", "", text)
        if len(digits) >= 4:
            return "***-***-" + digits[-4:]
        return "***"

    def validate(self, params: dict | None = None) -> None:
        pass

    def operator_name(self) -> str:
        return "partial_phone_mask"

    def operator_type(self) -> OperatorType:
        return OperatorType.Anonymize


class PartialSSNMask(Operator):
    """123-45-6789 → ***-**-6789"""

    def operate(self, text: str, params: dict | None = None) -> str:
        digits = re.sub(r"\D", "", text)
        if len(digits) >= 4:
            return "***-**-" + digits[-4:]
        return "***-**-****"

    def validate(self, params: dict | None = None) -> None:
        pass

    def operator_name(self) -> str:
        return "partial_ssn_mask"

    def operator_type(self) -> OperatorType:
        return OperatorType.Anonymize


class PartialNameMask(Operator):
    """John Doe → J*** D**"""

    def operate(self, text: str, params: dict | None = None) -> str:
        parts = text.split()
        masked = []
        for part in parts:
            if len(part) > 1:
                masked.append(part[0] + "*" * (len(part) - 1))
            elif part:
                masked.append(part[0] + "***")
            else:
                masked.append("***")
        return " ".join(masked)

    def validate(self, params: dict | None = None) -> None:
        pass

    def operator_name(self) -> str:
        return "partial_name_mask"

    def operator_type(self) -> OperatorType:
        return OperatorType.Anonymize


class PartialCreditCardMask(Operator):
    """4111-1111-1111-1111 → ****-****-****-1111"""

    def operate(self, text: str, params: dict | None = None) -> str:
        digits = re.sub(r"\D", "", text)
        if len(digits) >= 4:
            return "****-****-****-" + digits[-4:]
        return "****-****-****-****"

    def validate(self, params: dict | None = None) -> None:
        pass

    def operator_name(self) -> str:
        return "partial_credit_card_mask"

    def operator_type(self) -> OperatorType:
        return OperatorType.Anonymize


class PartialIPMask(Operator):
    """192.168.1.100 → ***.***.***.100"""

    def operate(self, text: str, params: dict | None = None) -> str:
        parts = text.split(".")
        if len(parts) == 4:
            return f"***.***.***.{parts[3]}"
        return "***.***.***. ***"

    def validate(self, params: dict | None = None) -> None:
        pass

    def operator_name(self) -> str:
        return "partial_ip_mask"

    def operator_type(self) -> OperatorType:
        return OperatorType.Anonymize


class PartialLocationMask(Operator):
    """123 Main St → *** Main St"""

    def operate(self, text: str, params: dict | None = None) -> str:
        # Mask leading numbers (street number)
        masked = re.sub(r"^\d+", "***", text)
        if masked == text:
            return _generic_partial(text)
        return masked

    def validate(self, params: dict | None = None) -> None:
        pass

    def operator_name(self) -> str:
        return "partial_location_mask"

    def operator_type(self) -> OperatorType:
        return OperatorType.Anonymize


class PartialFinancialMask(Operator):
    """Show last 4 digits only: 123456789 → *****6789"""

    def operate(self, text: str, params: dict | None = None) -> str:
        digits = re.sub(r"\D", "", text)
        if len(digits) >= 4:
            return "*" * (len(digits) - 4) + digits[-4:]
        return "****"

    def validate(self, params: dict | None = None) -> None:
        pass

    def operator_name(self) -> str:
        return "partial_financial_mask"

    def operator_type(self) -> OperatorType:
        return OperatorType.Anonymize


class PartialGenericMask(Operator):
    """Keep first char, mask rest: anything → a*******"""

    def operate(self, text: str, params: dict | None = None) -> str:
        return _generic_partial(text)

    def validate(self, params: dict | None = None) -> None:
        pass

    def operator_name(self) -> str:
        return "partial_generic_mask"

    def operator_type(self) -> OperatorType:
        return OperatorType.Anonymize


class PseudonymizeOperator(Operator):
    """Deterministic hash-based pseudonym: john@example.com → user_a3f2@masked.invalid"""

    def operate(self, text: str, params: dict | None = None) -> str:
        params = params or {}
        seed = params.get("seed", "postgres-safe-mcp")
        entity_type = params.get("entity_type", "UNKNOWN")
        h = hashlib.sha256(f"{seed}:{text}".encode()).hexdigest()[:8]
        return _pseudo_format(entity_type, h)

    def validate(self, params: dict | None = None) -> None:
        pass

    def operator_name(self) -> str:
        return "pseudonymize"

    def operator_type(self) -> OperatorType:
        return OperatorType.Anonymize


def _generic_partial(text: str) -> str:
    """Keep first char, mask rest."""
    if len(text) <= 1:
        return "***"
    return text[0] + "*" * (len(text) - 1)


def _pseudo_format(entity_type: str, hash_hex: str) -> str:
    """Generate a type-appropriate pseudonym."""
    match entity_type:
        case "EMAIL_ADDRESS":
            return f"user_{hash_hex}@masked.invalid"
        case "PHONE_NUMBER":
            return f"555-000-{hash_hex[:4]}"
        case "PERSON":
            return f"Person_{hash_hex[:6]}"
        case "LOCATION":
            return f"Location_{hash_hex[:6]}"
        case "US_SSN":
            return f"000-00-{hash_hex[:4]}"
        case "CREDIT_CARD":
            return f"0000-0000-0000-{hash_hex[:4]}"
        case _:
            return f"PSEUDO_{hash_hex}"


# --- All custom operators for registration ---

ALL_CUSTOM_OPERATORS: list[type[Operator]] = [
    PartialEmailMask,
    PartialPhoneMask,
    PartialSSNMask,
    PartialNameMask,
    PartialCreditCardMask,
    PartialIPMask,
    PartialLocationMask,
    PartialFinancialMask,
    PartialGenericMask,
    PseudonymizeOperator,
]


# --- Mapping from entity type to operator config per masking style ---

# Partial masking: entity_type → operator name
PARTIAL_OPERATORS: dict[str, str] = {
    "EMAIL_ADDRESS": "partial_email_mask",
    "PHONE_NUMBER": "partial_phone_mask",
    "US_SSN": "partial_ssn_mask",
    "PERSON": "partial_name_mask",
    "CREDIT_CARD": "partial_credit_card_mask",
    "IP_ADDRESS": "partial_ip_mask",
    "LOCATION": "partial_location_mask",
    "FINANCIAL": "partial_financial_mask",
    "DATE_TIME": "partial_generic_mask",
    "US_PASSPORT": "partial_generic_mask",
    "US_DRIVER_LICENSE": "partial_generic_mask",
}


def get_operator_config(
    entity_type: str,
    masking_style: str,
    pseudo_seed: str = "postgres-safe-mcp",
) -> OperatorConfig:
    """Get the appropriate OperatorConfig for an entity type and masking style."""
    if entity_type == "SECRET":
        # Secrets are always fully redacted
        return OperatorConfig("replace", {"new_value": "[REDACTED]"})

    match masking_style:
        case "full":
            label = entity_type.replace("_", " ").upper()
            return OperatorConfig("replace", {"new_value": f"[{label}]"})
        case "pseudonymize":
            return OperatorConfig(
                "pseudonymize",
                {"seed": pseudo_seed, "entity_type": entity_type},
            )
        case "none":
            return OperatorConfig("keep", {})
        case _:  # "partial" (default)
            op_name = PARTIAL_OPERATORS.get(entity_type, "partial_generic_mask")
            return OperatorConfig(op_name, {})


def mask_value(
    value: Any,
    entity_type: str,
    masking_style: str,
    pseudo_seed: str = "postgres-safe-mcp",
) -> Any:
    """Directly mask a single value without going through Presidio anonymizer.

    This is the fast path used for column-level masking where we already
    know the entity type.
    """
    if value is None:
        return None

    text = str(value)
    if not text.strip():
        return value

    if entity_type == "SECRET":
        return "[REDACTED]"

    match masking_style:
        case "full":
            label = entity_type.replace("_", " ").upper()
            return f"[{label}]"
        case "pseudonymize":
            h = hashlib.sha256(f"{pseudo_seed}:{text}".encode()).hexdigest()[:8]
            return _pseudo_format(entity_type, h)
        case "none":
            return value
        case _:  # "partial"
            return _apply_partial_mask(text, entity_type)


def _apply_partial_mask(text: str, entity_type: str) -> str:
    """Apply the appropriate partial masker directly (no Presidio operator overhead)."""
    match entity_type:
        case "EMAIL_ADDRESS":
            return PartialEmailMask().operate(text)
        case "PHONE_NUMBER":
            return PartialPhoneMask().operate(text)
        case "US_SSN":
            return PartialSSNMask().operate(text)
        case "PERSON":
            return PartialNameMask().operate(text)
        case "CREDIT_CARD":
            return PartialCreditCardMask().operate(text)
        case "IP_ADDRESS":
            return PartialIPMask().operate(text)
        case "LOCATION":
            return PartialLocationMask().operate(text)
        case "FINANCIAL":
            return PartialFinancialMask().operate(text)
        case _:
            return _generic_partial(text)
