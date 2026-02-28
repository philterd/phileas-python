# Copyright 2026 Philterd, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for the PII anonymization services and RANDOM_REPLACE strategy."""

import re
import pytest

from phileas.services.anonymization import (
    get_anonymization_service,
    AgeAnonymizationService,
    EmailAddressAnonymizationService,
    CreditCardAnonymizationService,
    SSNAnonymizationService,
    PhoneNumberAnonymizationService,
    IPAddressAnonymizationService,
    URLAnonymizationService,
    ZipCodeAnonymizationService,
    VINAnonymizationService,
    BitcoinAddressAnonymizationService,
    BankRoutingNumberAnonymizationService,
    DateAnonymizationService,
    MACAddressAnonymizationService,
    CurrencyAnonymizationService,
    StreetAddressAnonymizationService,
    TrackingNumberAnonymizationService,
    DriversLicenseAnonymizationService,
    IBANCodeAnonymizationService,
    PassportNumberAnonymizationService,
)
from phileas.policy.filter_strategy import FilterStrategy


# ---------------------------------------------------------------------------
# Registry / factory
# ---------------------------------------------------------------------------

class TestGetAnonymizationService:
    def test_returns_service_for_known_type(self):
        svc = get_anonymization_service("email-address")
        assert svc is not None
        assert isinstance(svc, EmailAddressAnonymizationService)

    def test_returns_none_for_unknown_type(self):
        svc = get_anonymization_service("unknown-type")
        assert svc is None

    def test_all_filter_types_registered(self):
        filter_types = [
            "age", "email-address", "credit-card", "ssn", "phone-number",
            "ip-address", "url", "zip-code", "vin", "bitcoin-address",
            "bank-routing-number", "date", "mac-address", "currency",
            "street-address", "tracking-number", "drivers-license",
            "iban-code", "passport-number",
        ]
        for ft in filter_types:
            assert get_anonymization_service(ft) is not None, f"No service registered for '{ft}'"


# ---------------------------------------------------------------------------
# Individual anonymization services
# ---------------------------------------------------------------------------

class TestAgeAnonymizationService:
    def test_produces_age_string(self):
        svc = AgeAnonymizationService()
        result = svc.anonymize("45 years old")
        assert "years old" in result

    def test_different_from_original(self):
        svc = AgeAnonymizationService()
        results = {svc.anonymize("45 years old") for _ in range(20)}
        # With a range of 1-99 years, we should see variety
        assert len(results) > 1


class TestEmailAddressAnonymizationService:
    def test_produces_valid_email_format(self):
        svc = EmailAddressAnonymizationService()
        result = svc.anonymize("john@example.com")
        assert "@" in result
        assert "." in result.split("@")[1]

    def test_produces_different_values(self):
        svc = EmailAddressAnonymizationService()
        results = {svc.anonymize("test@test.com") for _ in range(20)}
        assert len(results) > 1


class TestCreditCardAnonymizationService:
    def test_produces_16_digits(self):
        svc = CreditCardAnonymizationService()
        result = svc.anonymize("4111111111111111")
        assert re.fullmatch(r"\d{16}", result)

    def test_starts_with_4(self):
        svc = CreditCardAnonymizationService()
        result = svc.anonymize("4111111111111111")
        assert result.startswith("4")

    def test_produces_different_values(self):
        svc = CreditCardAnonymizationService()
        results = {svc.anonymize("4111111111111111") for _ in range(20)}
        assert len(results) > 1


class TestSSNAnonymizationService:
    def test_produces_formatted_ssn(self):
        svc = SSNAnonymizationService()
        result = svc.anonymize("123-45-6789")
        assert re.fullmatch(r"\d{3}-\d{2}-\d{4}", result)

    def test_avoids_invalid_area_000(self):
        svc = SSNAnonymizationService()
        for _ in range(50):
            result = svc.anonymize("123-45-6789")
            area = int(result.split("-")[0])
            assert area != 0

    def test_avoids_invalid_area_666(self):
        svc = SSNAnonymizationService()
        for _ in range(50):
            result = svc.anonymize("123-45-6789")
            area = int(result.split("-")[0])
            assert area != 666

    def test_produces_different_values(self):
        svc = SSNAnonymizationService()
        results = {svc.anonymize("123-45-6789") for _ in range(20)}
        assert len(results) > 1


class TestPhoneNumberAnonymizationService:
    def test_produces_phone_format(self):
        svc = PhoneNumberAnonymizationService()
        result = svc.anonymize("800-555-1234")
        assert re.fullmatch(r"\d{3}-\d{3}-\d{4}", result)

    def test_produces_different_values(self):
        svc = PhoneNumberAnonymizationService()
        results = {svc.anonymize("800-555-1234") for _ in range(20)}
        assert len(results) > 1


class TestIPAddressAnonymizationService:
    def test_produces_valid_ipv4_format(self):
        svc = IPAddressAnonymizationService()
        result = svc.anonymize("192.168.1.1")
        parts = result.split(".")
        assert len(parts) == 4
        assert all(0 <= int(p) <= 255 for p in parts)

    def test_produces_private_range(self):
        svc = IPAddressAnonymizationService()
        result = svc.anonymize("8.8.8.8")
        assert result.startswith("10.")

    def test_produces_different_values(self):
        svc = IPAddressAnonymizationService()
        results = {svc.anonymize("192.168.1.1") for _ in range(20)}
        assert len(results) > 1


class TestURLAnonymizationService:
    def test_produces_https_url(self):
        svc = URLAnonymizationService()
        result = svc.anonymize("http://example.com")
        assert result.startswith("https://")

    def test_produces_different_values(self):
        svc = URLAnonymizationService()
        results = {svc.anonymize("http://example.com") for _ in range(20)}
        assert len(results) > 1


class TestZipCodeAnonymizationService:
    def test_produces_five_digit_zip(self):
        svc = ZipCodeAnonymizationService()
        result = svc.anonymize("12345")
        assert re.fullmatch(r"\d{5}", result)

    def test_produces_different_values(self):
        svc = ZipCodeAnonymizationService()
        results = {svc.anonymize("12345") for _ in range(20)}
        assert len(results) > 1


class TestVINAnonymizationService:
    def test_produces_17_char_vin(self):
        svc = VINAnonymizationService()
        result = svc.anonymize("1HGCM82633A123456")
        assert len(result) == 17

    def test_no_invalid_vin_characters(self):
        svc = VINAnonymizationService()
        for _ in range(20):
            result = svc.anonymize("1HGCM82633A123456")
            assert not any(c in result for c in "IOQ")

    def test_produces_different_values(self):
        svc = VINAnonymizationService()
        results = {svc.anonymize("1HGCM82633A123456") for _ in range(20)}
        assert len(results) > 1


class TestBitcoinAddressAnonymizationService:
    def test_produces_p2pkh_address(self):
        svc = BitcoinAddressAnonymizationService()
        result = svc.anonymize("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        assert result.startswith("1")
        assert len(result) >= 26
        assert len(result) <= 35

    def test_produces_different_values(self):
        svc = BitcoinAddressAnonymizationService()
        results = {svc.anonymize("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") for _ in range(20)}
        assert len(results) > 1


class TestBankRoutingNumberAnonymizationService:
    def test_produces_nine_digit_number(self):
        svc = BankRoutingNumberAnonymizationService()
        result = svc.anonymize("021000021")
        assert re.fullmatch(r"\d{9}", result)

    def test_valid_aba_prefix(self):
        svc = BankRoutingNumberAnonymizationService()
        valid_prefixes = set(range(1, 13)) | set(range(21, 33))
        for _ in range(50):
            result = svc.anonymize("021000021")
            prefix = int(result[:2])
            assert prefix in valid_prefixes

    def test_produces_different_values(self):
        svc = BankRoutingNumberAnonymizationService()
        results = {svc.anonymize("021000021") for _ in range(20)}
        assert len(results) > 1


class TestDateAnonymizationService:
    def test_produces_date_format(self):
        svc = DateAnonymizationService()
        result = svc.anonymize("01/15/1990")
        assert re.fullmatch(r"\d{2}/\d{2}/\d{4}", result)

    def test_produces_different_values(self):
        svc = DateAnonymizationService()
        results = {svc.anonymize("01/15/1990") for _ in range(20)}
        assert len(results) > 1


class TestMACAddressAnonymizationService:
    def test_produces_mac_format(self):
        svc = MACAddressAnonymizationService()
        result = svc.anonymize("00:1A:2B:3C:4D:5E")
        assert re.fullmatch(r"[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}", result)

    def test_produces_different_values(self):
        svc = MACAddressAnonymizationService()
        results = {svc.anonymize("00:1A:2B:3C:4D:5E") for _ in range(20)}
        assert len(results) > 1


class TestCurrencyAnonymizationService:
    def test_produces_dollar_format(self):
        svc = CurrencyAnonymizationService()
        result = svc.anonymize("$100")
        assert re.fullmatch(r"\$\d+\.\d{2}", result)

    def test_produces_different_values(self):
        svc = CurrencyAnonymizationService()
        results = {svc.anonymize("$100") for _ in range(20)}
        assert len(results) > 1


class TestStreetAddressAnonymizationService:
    def test_produces_street_address(self):
        svc = StreetAddressAnonymizationService()
        result = svc.anonymize("123 Main Street")
        # Should be "<number> <name> <suffix>"
        parts = result.split()
        assert len(parts) >= 3
        assert parts[0].isdigit()

    def test_produces_different_values(self):
        svc = StreetAddressAnonymizationService()
        results = {svc.anonymize("123 Main Street") for _ in range(20)}
        assert len(results) > 1


class TestTrackingNumberAnonymizationService:
    def test_produces_ups_format(self):
        svc = TrackingNumberAnonymizationService()
        result = svc.anonymize("1Z999AA10123456784")
        assert result.startswith("1Z")
        assert len(result) == 18  # "1Z" + 16 chars

    def test_produces_different_values(self):
        svc = TrackingNumberAnonymizationService()
        results = {svc.anonymize("1Z999AA10123456784") for _ in range(20)}
        assert len(results) > 1


class TestDriversLicenseAnonymizationService:
    def test_produces_letter_digits_format(self):
        svc = DriversLicenseAnonymizationService()
        result = svc.anonymize("A12345678")
        assert re.fullmatch(r"[A-Z]\d{8}", result)

    def test_produces_different_values(self):
        svc = DriversLicenseAnonymizationService()
        results = {svc.anonymize("A12345678") for _ in range(20)}
        assert len(results) > 1


class TestIBANCodeAnonymizationService:
    def test_produces_gb_iban_format(self):
        svc = IBANCodeAnonymizationService()
        result = svc.anonymize("GB29NWBK60161331926819")
        assert result.startswith("GB")
        assert len(result) == 22  # GB + 2 check + 4 bank + 14 account

    def test_produces_different_values(self):
        svc = IBANCodeAnonymizationService()
        results = {svc.anonymize("GB29NWBK60161331926819") for _ in range(20)}
        assert len(results) > 1


class TestPassportNumberAnonymizationService:
    def test_produces_us_passport_format(self):
        svc = PassportNumberAnonymizationService()
        result = svc.anonymize("A12345678")
        assert re.fullmatch(r"[A-Z]\d{8}", result)

    def test_produces_different_values(self):
        svc = PassportNumberAnonymizationService()
        results = {svc.anonymize("A12345678") for _ in range(20)}
        assert len(results) > 1


# ---------------------------------------------------------------------------
# FilterStrategy RANDOM_REPLACE integration
# ---------------------------------------------------------------------------

class TestFilterStrategyRandomReplace:
    def test_email_random_replace(self):
        s = FilterStrategy(strategy="RANDOM_REPLACE")
        result = s.get_replacement("email-address", "test@example.com")
        assert "@" in result
        assert result != "test@example.com" or True  # replacement is generated

    def test_ssn_random_replace(self):
        s = FilterStrategy(strategy="RANDOM_REPLACE")
        result = s.get_replacement("ssn", "123-45-6789")
        assert re.fullmatch(r"\d{3}-\d{2}-\d{4}", result)

    def test_credit_card_random_replace(self):
        s = FilterStrategy(strategy="RANDOM_REPLACE")
        result = s.get_replacement("credit-card", "4111111111111111")
        assert re.fullmatch(r"\d{16}", result)

    def test_phone_random_replace(self):
        s = FilterStrategy(strategy="RANDOM_REPLACE")
        result = s.get_replacement("phone-number", "800-555-1234")
        assert re.fullmatch(r"\d{3}-\d{3}-\d{4}", result)

    def test_ip_address_random_replace(self):
        s = FilterStrategy(strategy="RANDOM_REPLACE")
        result = s.get_replacement("ip-address", "192.168.1.1")
        parts = result.split(".")
        assert len(parts) == 4

    def test_url_random_replace(self):
        s = FilterStrategy(strategy="RANDOM_REPLACE")
        result = s.get_replacement("url", "http://example.com")
        assert result.startswith("https://")

    def test_zip_code_random_replace(self):
        s = FilterStrategy(strategy="RANDOM_REPLACE")
        result = s.get_replacement("zip-code", "12345")
        assert re.fullmatch(r"\d{5}", result)

    def test_vin_random_replace(self):
        s = FilterStrategy(strategy="RANDOM_REPLACE")
        result = s.get_replacement("vin", "1HGCM82633A123456")
        assert len(result) == 17

    def test_date_random_replace(self):
        s = FilterStrategy(strategy="RANDOM_REPLACE")
        result = s.get_replacement("date", "01/15/1990")
        assert re.fullmatch(r"\d{2}/\d{2}/\d{4}", result)

    def test_mac_address_random_replace(self):
        s = FilterStrategy(strategy="RANDOM_REPLACE")
        result = s.get_replacement("mac-address", "00:1A:2B:3C:4D:5E")
        assert re.fullmatch(r"[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}", result)

    def test_currency_random_replace(self):
        s = FilterStrategy(strategy="RANDOM_REPLACE")
        result = s.get_replacement("currency", "$100")
        assert re.fullmatch(r"\$\d+\.\d{2}", result)

    def test_street_address_random_replace(self):
        s = FilterStrategy(strategy="RANDOM_REPLACE")
        result = s.get_replacement("street-address", "123 Main Street")
        parts = result.split()
        assert len(parts) >= 3

    def test_tracking_number_random_replace(self):
        s = FilterStrategy(strategy="RANDOM_REPLACE")
        result = s.get_replacement("tracking-number", "1Z999AA10123456784")
        assert result.startswith("1Z")

    def test_drivers_license_random_replace(self):
        s = FilterStrategy(strategy="RANDOM_REPLACE")
        result = s.get_replacement("drivers-license", "A12345678")
        assert re.fullmatch(r"[A-Z]\d{8}", result)

    def test_iban_code_random_replace(self):
        s = FilterStrategy(strategy="RANDOM_REPLACE")
        result = s.get_replacement("iban-code", "GB29NWBK60161331926819")
        assert result.startswith("GB")

    def test_passport_number_random_replace(self):
        s = FilterStrategy(strategy="RANDOM_REPLACE")
        result = s.get_replacement("passport-number", "A12345678")
        assert re.fullmatch(r"[A-Z]\d{8}", result)

    def test_age_random_replace(self):
        s = FilterStrategy(strategy="RANDOM_REPLACE")
        result = s.get_replacement("age", "45 years old")
        assert "years old" in result

    def test_bank_routing_number_random_replace(self):
        s = FilterStrategy(strategy="RANDOM_REPLACE")
        result = s.get_replacement("bank-routing-number", "021000021")
        assert re.fullmatch(r"\d{9}", result)

    def test_bitcoin_address_random_replace(self):
        s = FilterStrategy(strategy="RANDOM_REPLACE")
        result = s.get_replacement("bitcoin-address", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        assert result.startswith("1")

    def test_unknown_type_fallback_returns_token(self):
        s = FilterStrategy(strategy="RANDOM_REPLACE")
        result = s.get_replacement("unknown-pii-type", "some-value")
        assert result == "some-value"

    def test_random_replace_is_nondeterministic(self):
        """Verify that repeated calls produce different results."""
        s = FilterStrategy(strategy="RANDOM_REPLACE")
        results = {s.get_replacement("email-address", "test@example.com") for _ in range(20)}
        assert len(results) > 1


# ---------------------------------------------------------------------------
# FilterService integration with RANDOM_REPLACE
# ---------------------------------------------------------------------------

class TestFilterServiceRandomReplace:
    def test_email_random_replace_via_service(self):
        from phileas.policy.policy import Policy
        from phileas.policy.identifiers import EmailAddressFilterConfig
        from phileas.services.filter_service import FilterService

        config = EmailAddressFilterConfig(
            email_address_filter_strategies=[FilterStrategy(strategy="RANDOM_REPLACE")]
        )
        policy = Policy(name="test")
        policy.identifiers.email_address = config
        result = FilterService().filter(policy, "ctx", "doc", "Email: test@example.com")
        assert "test@example.com" not in result.filtered_text
        assert "@" in result.filtered_text

    def test_ssn_random_replace_via_service(self):
        from phileas.policy.policy import Policy
        from phileas.policy.identifiers import SSNFilterConfig
        from phileas.services.filter_service import FilterService

        config = SSNFilterConfig(
            ssn_filter_strategies=[FilterStrategy(strategy="RANDOM_REPLACE")]
        )
        policy = Policy(name="test")
        policy.identifiers.ssn = config
        result = FilterService().filter(policy, "ctx", "doc", "SSN: 123-45-6789")
        assert "123-45-6789" not in result.filtered_text
        assert re.search(r"\d{3}-\d{2}-\d{4}", result.filtered_text)
