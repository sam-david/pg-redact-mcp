"""Tests for PII detection."""

from postgres_safe_mcp.redaction.detector import PiiDetector


class TestColumnNameHeuristics:
    def setup_method(self):
        # Create detector without Presidio (no NLP model needed for heuristic tests)
        self._detector = PiiDetector(analyzer=None)

    def test_email_column(self):
        info = self._detector.detect_column_pii("email")
        assert info is not None
        assert info.entity_type == "EMAIL_ADDRESS"

    def test_prefixed_email(self):
        for col in ["pref_email", "bus_email", "other_email", "sender_email_address"]:
            info = self._detector.detect_column_pii(col)
            assert info is not None, f"Failed for {col}"
            assert info.entity_type == "EMAIL_ADDRESS", f"Wrong type for {col}"

    def test_phone_columns(self):
        for col in ["phone", "cell_phone", "home_phone", "bus_phone", "rep_phone_number", "mobile"]:
            info = self._detector.detect_column_pii(col)
            assert info is not None, f"Failed for {col}"
            assert info.entity_type == "PHONE_NUMBER", f"Wrong type for {col}"

    def test_name_columns(self):
        for col in [
            "first_name", "last_name", "full_name", "middle_name",
            "former_last_name", "spouse_name", "pref_first_name",
            "account_holder_name", "payer_name", "paid_name",
            "nickname",
        ]:
            info = self._detector.detect_column_pii(col)
            assert info is not None, f"Failed for {col}"
            assert info.entity_type == "PERSON", f"Wrong type for {col}"

    def test_address_columns(self):
        for col in [
            "address", "street", "address_line_1", "bus_street1",
            "city", "state", "zipcode", "postal_code", "country",
        ]:
            info = self._detector.detect_column_pii(col)
            assert info is not None, f"Failed for {col}"
            assert info.entity_type == "LOCATION", f"Wrong type for {col}"

    def test_ssn_tax_columns(self):
        for col in ["ssn", "rep_ssn_last_4", "business_tax_id", "ein", "cpf"]:
            info = self._detector.detect_column_pii(col)
            assert info is not None, f"Failed for {col}"
            assert info.entity_type == "US_SSN", f"Wrong type for {col}"

    def test_dob_columns(self):
        for col in ["date_of_birth", "dob", "birth_date", "rep_dob_month"]:
            info = self._detector.detect_column_pii(col)
            assert info is not None, f"Failed for {col}"
            assert info.entity_type == "DATE_TIME", f"Wrong type for {col}"

    def test_ip_columns(self):
        for col in ["ip_address", "remote_address", "current_sign_in_ip"]:
            info = self._detector.detect_column_pii(col)
            assert info is not None, f"Failed for {col}"
            assert info.entity_type == "IP_ADDRESS", f"Wrong type for {col}"

    def test_secret_columns(self):
        for col in ["encrypted_password", "otp_secret_key", "reset_password_token"]:
            info = self._detector.detect_column_pii(col)
            assert info is not None, f"Failed for {col}"
            assert info.entity_type == "SECRET", f"Wrong type for {col}"

    def test_geolocation_columns(self):
        for col in ["lat", "lon", "latitude", "longitude"]:
            info = self._detector.detect_column_pii(col)
            assert info is not None, f"Failed for {col}"
            assert info.entity_type == "LOCATION", f"Wrong type for {col}"

    def test_free_text_columns(self):
        for col in ["raw_message", "display_body", "content", "description", "notes"]:
            info = self._detector.detect_column_pii(col)
            assert info is not None, f"Failed for {col}"
            assert info.is_free_text, f"Should be free_text for {col}"

    def test_non_pii_columns(self):
        for col in ["id", "created_at", "updated_at", "status", "amount", "count"]:
            info = self._detector.detect_column_pii(col)
            assert info is None, f"Should be None for {col}"

    def test_credit_card_columns(self):
        for col in ["credit_card", "card_number"]:
            info = self._detector.detect_column_pii(col)
            assert info is not None, f"Failed for {col}"
            assert info.entity_type == "CREDIT_CARD", f"Wrong type for {col}"

    def test_financial_columns(self):
        for col in ["routing_number", "bank_account", "account_number"]:
            info = self._detector.detect_column_pii(col)
            assert info is not None, f"Failed for {col}"
            assert info.entity_type == "FINANCIAL", f"Wrong type for {col}"


class TestManualOverrides:
    def test_set_and_get_override(self):
        detector = PiiDetector(analyzer=None)
        detector.set_manual_override("public.users", "email", "EMAIL_ADDRESS")
        info = detector.get_cached_info("public.users", "email")
        assert info is not None
        assert info.entity_type == "EMAIL_ADDRESS"
        assert info.source == "manual"

    def test_set_none_clears(self):
        detector = PiiDetector(analyzer=None)
        detector.set_manual_override("public.users", "email", "EMAIL_ADDRESS")
        detector.set_manual_override("public.users", "email", "none")
        info = detector.get_cached_info("public.users", "email")
        assert info is None
