"""Tests for masking operators."""

from postgres_safe_mcp.redaction.maskers import (
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
    mask_value,
)


class TestPartialEmailMask:
    def test_standard_email(self):
        assert PartialEmailMask().operate("john@example.com") == "j***@e***.com"

    def test_short_local(self):
        assert PartialEmailMask().operate("a@b.com") == "a***@b***.com"

    def test_no_at_sign(self):
        # Falls back to generic partial
        result = PartialEmailMask().operate("notanemail")
        assert result == "n*********"

    def test_subdomain(self):
        result = PartialEmailMask().operate("user@mail.example.com")
        assert result == "u***@m***.com"


class TestPartialPhoneMask:
    def test_us_format(self):
        assert PartialPhoneMask().operate("555-123-4567") == "***-***-4567"

    def test_with_parens(self):
        assert PartialPhoneMask().operate("(555) 123-4567") == "***-***-4567"

    def test_digits_only(self):
        assert PartialPhoneMask().operate("5551234567") == "***-***-4567"

    def test_short_number(self):
        assert PartialPhoneMask().operate("123") == "***"


class TestPartialSSNMask:
    def test_standard_ssn(self):
        assert PartialSSNMask().operate("123-45-6789") == "***-**-6789"

    def test_digits_only(self):
        assert PartialSSNMask().operate("123456789") == "***-**-6789"


class TestPartialNameMask:
    def test_full_name(self):
        assert PartialNameMask().operate("John Doe") == "J*** D**"

    def test_single_name(self):
        assert PartialNameMask().operate("Madonna") == "M******"

    def test_three_parts(self):
        assert PartialNameMask().operate("John Q Public") == "J*** Q*** P*****"

    def test_single_char_name(self):
        result = PartialNameMask().operate("J")
        assert result == "J***"


class TestPartialCreditCardMask:
    def test_with_dashes(self):
        assert (
            PartialCreditCardMask().operate("4111-1111-1111-1111")
            == "****-****-****-1111"
        )

    def test_digits_only(self):
        assert (
            PartialCreditCardMask().operate("4111111111111111")
            == "****-****-****-1111"
        )


class TestPartialIPMask:
    def test_ipv4(self):
        assert PartialIPMask().operate("192.168.1.100") == "***.***.***.100"

    def test_localhost(self):
        assert PartialIPMask().operate("127.0.0.1") == "***.***.***.1"


class TestPartialLocationMask:
    def test_street_address(self):
        assert PartialLocationMask().operate("123 Main St") == "*** Main St"

    def test_no_number(self):
        # Falls back to generic partial
        result = PartialLocationMask().operate("Main Street")
        assert result == "M**********"


class TestPartialFinancialMask:
    def test_account_number(self):
        assert PartialFinancialMask().operate("123456789") == "*****6789"

    def test_short_number(self):
        assert PartialFinancialMask().operate("12") == "****"


class TestPartialGenericMask:
    def test_generic(self):
        assert PartialGenericMask().operate("something") == "s********"

    def test_single_char(self):
        assert PartialGenericMask().operate("x") == "***"


class TestPseudonymize:
    def test_deterministic(self):
        op = PseudonymizeOperator()
        params = {"seed": "test", "entity_type": "EMAIL_ADDRESS"}
        result1 = op.operate("john@example.com", params)
        result2 = op.operate("john@example.com", params)
        assert result1 == result2

    def test_different_inputs_different_output(self):
        op = PseudonymizeOperator()
        params = {"seed": "test", "entity_type": "EMAIL_ADDRESS"}
        result1 = op.operate("john@example.com", params)
        result2 = op.operate("jane@example.com", params)
        assert result1 != result2

    def test_email_format(self):
        op = PseudonymizeOperator()
        result = op.operate("john@example.com", {"seed": "s", "entity_type": "EMAIL_ADDRESS"})
        assert "@masked.invalid" in result

    def test_phone_format(self):
        op = PseudonymizeOperator()
        result = op.operate("555-1234", {"seed": "s", "entity_type": "PHONE_NUMBER"})
        assert result.startswith("555-000-")

    def test_person_format(self):
        op = PseudonymizeOperator()
        result = op.operate("John Doe", {"seed": "s", "entity_type": "PERSON"})
        assert result.startswith("Person_")


class TestMaskValue:
    def test_none_passthrough(self):
        assert mask_value(None, "EMAIL_ADDRESS", "partial") is None

    def test_empty_string_passthrough(self):
        assert mask_value("", "EMAIL_ADDRESS", "partial") == ""

    def test_secret_always_redacted(self):
        assert mask_value("supersecret", "SECRET", "partial") == "[REDACTED]"
        assert mask_value("supersecret", "SECRET", "none") == "[REDACTED]"
        assert mask_value("supersecret", "SECRET", "pseudonymize") == "[REDACTED]"

    def test_full_redaction(self):
        assert mask_value("john@test.com", "EMAIL_ADDRESS", "full") == "[EMAIL ADDRESS]"

    def test_partial_email(self):
        assert mask_value("john@example.com", "EMAIL_ADDRESS", "partial") == "j***@e***.com"

    def test_none_style(self):
        assert mask_value("john@example.com", "EMAIL_ADDRESS", "none") == "john@example.com"

    def test_pseudonymize(self):
        result = mask_value("john@example.com", "EMAIL_ADDRESS", "pseudonymize")
        assert "@masked.invalid" in result
