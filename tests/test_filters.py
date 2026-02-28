"""Tests for individual PII/PHI filters."""

import json
import pytest

from phileas.policy.filter_strategy import FilterStrategy
from phileas.policy.identifiers import (
    AgeFilterConfig,
    EmailAddressFilterConfig,
    CreditCardFilterConfig,
    SSNFilterConfig,
    PhoneNumberFilterConfig,
    IPAddressFilterConfig,
    URLFilterConfig,
    ZipCodeFilterConfig,
    VINFilterConfig,
    BitcoinAddressFilterConfig,
    BankRoutingNumberFilterConfig,
    DateFilterConfig,
    MACAddressFilterConfig,
    CurrencyFilterConfig,
    StreetAddressFilterConfig,
    TrackingNumberFilterConfig,
    IBANCodeFilterConfig,
    PassportNumberFilterConfig,
    PhEyeFilterConfig,
)
from phileas.filters.age_filter import AgeFilter
from phileas.filters.email_address_filter import EmailAddressFilter
from phileas.filters.credit_card_filter import CreditCardFilter
from phileas.filters.ssn_filter import SSNFilter
from phileas.filters.phone_number_filter import PhoneNumberFilter
from phileas.filters.ip_address_filter import IPAddressFilter
from phileas.filters.url_filter import URLFilter
from phileas.filters.zip_code_filter import ZipCodeFilter
from phileas.filters.vin_filter import VINFilter
from phileas.filters.bitcoin_address_filter import BitcoinAddressFilter
from phileas.filters.bank_routing_number_filter import BankRoutingNumberFilter
from phileas.filters.date_filter import DateFilter
from phileas.filters.mac_address_filter import MACAddressFilter
from phileas.filters.currency_filter import CurrencyFilter
from phileas.filters.street_address_filter import StreetAddressFilter
from phileas.filters.tracking_number_filter import TrackingNumberFilter
from phileas.filters.iban_code_filter import IBANCodeFilter
from phileas.filters.passport_number_filter import PassportNumberFilter
from phileas.filters.ph_eye_filter import PhEyeFilter


def _default_config(config_cls):
    return config_cls()


# ---------------------------------------------------------------------------
# Age Filter
# ---------------------------------------------------------------------------

class TestAgeFilter:
    def setup_method(self):
        self.f = AgeFilter(_default_config(AgeFilterConfig))

    def test_age_years_old(self):
        spans = self.f.filter("The patient is 45 years old.")
        assert any("45" in s.text for s in spans)

    def test_age_yr(self):
        spans = self.f.filter("He is a 30 yr old male.")
        assert any("30" in s.text for s in spans)

    def test_age_yo(self):
        spans = self.f.filter("She is 25 yo.")
        assert any("25" in s.text for s in spans)

    def test_age_prefix(self):
        spans = self.f.filter("Age: 55 patient presents.")
        assert any("55" in s.text for s in spans)

    def test_age_hyphen(self):
        spans = self.f.filter("A 40-year-old woman.")
        assert any("40" in s.text for s in spans)

    def test_age_yo_slash(self):
        spans = self.f.filter("A 65 y/o male.")
        assert any("65" in s.text for s in spans)

    def test_no_false_positive_plain_number(self):
        spans = self.f.filter("There are 100 items.")
        assert len(spans) == 0

    def test_replacement(self):
        spans = self.f.filter("Patient is 45 years old.")
        assert all("{REDACTED" in s.replacement for s in spans)


# ---------------------------------------------------------------------------
# Email Address Filter
# ---------------------------------------------------------------------------

class TestEmailAddressFilter:
    def setup_method(self):
        self.f = EmailAddressFilter(_default_config(EmailAddressFilterConfig))

    def test_simple_email(self):
        spans = self.f.filter("Contact me at john.doe@example.com please.")
        assert len(spans) == 1
        assert spans[0].text == "john.doe@example.com"

    def test_email_with_subdomain(self):
        spans = self.f.filter("Send to user@mail.company.org")
        assert len(spans) == 1

    def test_no_email(self):
        spans = self.f.filter("No email here.")
        assert len(spans) == 0

    def test_multiple_emails(self):
        spans = self.f.filter("a@b.com and c@d.org")
        assert len(spans) == 2

    def test_replacement_default(self):
        spans = self.f.filter("Email: test@example.com")
        assert spans[0].replacement == "{{{REDACTED-email-address}}}"


# ---------------------------------------------------------------------------
# Credit Card Filter
# ---------------------------------------------------------------------------

class TestCreditCardFilter:
    def setup_method(self):
        self.f = CreditCardFilter(_default_config(CreditCardFilterConfig))

    def test_visa(self):
        spans = self.f.filter("Card: 4111111111111111")
        assert any("4111111111111111" in s.text for s in spans)

    def test_mastercard(self):
        spans = self.f.filter("Pay with 5500005555555559")
        assert len(spans) >= 1

    def test_amex(self):
        spans = self.f.filter("AmEx: 378282246310005")
        assert any("378282246310005" in s.text for s in spans)

    def test_discover(self):
        spans = self.f.filter("Discover: 6011111111111117")
        assert len(spans) >= 1

    def test_no_match(self):
        spans = self.f.filter("No card here.")
        assert len(spans) == 0


# ---------------------------------------------------------------------------
# SSN Filter
# ---------------------------------------------------------------------------

class TestSSNFilter:
    def setup_method(self):
        self.f = SSNFilter(_default_config(SSNFilterConfig))

    def test_formatted_ssn(self):
        spans = self.f.filter("SSN: 123-45-6789")
        assert len(spans) == 1
        assert spans[0].text == "123-45-6789"

    def test_unformatted_ssn(self):
        spans = self.f.filter("SSN 123456789")
        assert len(spans) >= 1

    def test_known_invalid_ssn(self):
        # 219-09-9999 is explicitly excluded
        spans = self.f.filter("SSN: 219-09-9999")
        assert len(spans) == 0

    def test_no_ssn(self):
        spans = self.f.filter("No SSN here.")
        assert len(spans) == 0


# ---------------------------------------------------------------------------
# Phone Number Filter
# ---------------------------------------------------------------------------

class TestPhoneNumberFilter:
    def setup_method(self):
        self.f = PhoneNumberFilter(_default_config(PhoneNumberFilterConfig))

    def test_dashes(self):
        spans = self.f.filter("Call 800-555-1234 now.")
        assert any("800-555-1234" in s.text for s in spans)

    def test_dots(self):
        spans = self.f.filter("Reach us at 800.555.1234.")
        assert any("800.555.1234" in s.text for s in spans)

    def test_parentheses(self):
        spans = self.f.filter("Call (800) 555-1234.")
        assert len(spans) >= 1

    def test_no_phone(self):
        spans = self.f.filter("No phone here.")
        assert len(spans) == 0


# ---------------------------------------------------------------------------
# IP Address Filter
# ---------------------------------------------------------------------------

class TestIPAddressFilter:
    def setup_method(self):
        self.f = IPAddressFilter(_default_config(IPAddressFilterConfig))

    def test_ipv4(self):
        spans = self.f.filter("Server at 192.168.1.100.")
        assert any("192.168.1.100" in s.text for s in spans)

    def test_ipv4_public(self):
        spans = self.f.filter("IP: 8.8.8.8")
        assert any("8.8.8.8" in s.text for s in spans)

    def test_ipv6(self):
        spans = self.f.filter("IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert len(spans) >= 1

    def test_no_ip(self):
        spans = self.f.filter("No IP here.")
        assert len(spans) == 0


# ---------------------------------------------------------------------------
# URL Filter
# ---------------------------------------------------------------------------

class TestURLFilter:
    def setup_method(self):
        self.f = URLFilter(_default_config(URLFilterConfig))

    def test_http(self):
        spans = self.f.filter("Visit http://example.com today.")
        assert len(spans) >= 1
        assert spans[0].text.startswith("http")

    def test_https(self):
        spans = self.f.filter("Go to https://www.example.com/path?q=1")
        assert len(spans) >= 1

    def test_no_url(self):
        spans = self.f.filter("No URL here.")
        assert len(spans) == 0


# ---------------------------------------------------------------------------
# Zip Code Filter
# ---------------------------------------------------------------------------

class TestZipCodeFilter:
    def setup_method(self):
        self.f = ZipCodeFilter(_default_config(ZipCodeFilterConfig))

    def test_five_digit(self):
        spans = self.f.filter("ZIP: 12345")
        assert any("12345" in s.text for s in spans)

    def test_five_plus_four(self):
        spans = self.f.filter("ZIP: 12345-6789")
        assert any("12345-6789" in s.text for s in spans)

    def test_no_zip(self):
        spans = self.f.filter("No zip here.")
        assert len(spans) == 0


# ---------------------------------------------------------------------------
# VIN Filter
# ---------------------------------------------------------------------------

class TestVINFilter:
    def setup_method(self):
        self.f = VINFilter(_default_config(VINFilterConfig))

    def test_valid_vin(self):
        spans = self.f.filter("VIN: 1HGCM82633A123456")
        assert any("1HGCM82633A123456" in s.text for s in spans)

    def test_no_vin(self):
        spans = self.f.filter("No VIN here.")
        assert len(spans) == 0


# ---------------------------------------------------------------------------
# Bitcoin Address Filter
# ---------------------------------------------------------------------------

class TestBitcoinAddressFilter:
    def setup_method(self):
        self.f = BitcoinAddressFilter(_default_config(BitcoinAddressFilterConfig))

    def test_p2pkh(self):
        spans = self.f.filter("Bitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        assert len(spans) >= 1

    def test_no_bitcoin(self):
        spans = self.f.filter("No bitcoin address here.")
        assert len(spans) == 0


# ---------------------------------------------------------------------------
# Bank Routing Number Filter
# ---------------------------------------------------------------------------

class TestBankRoutingNumberFilter:
    def setup_method(self):
        self.f = BankRoutingNumberFilter(_default_config(BankRoutingNumberFilterConfig))

    def test_routing_number(self):
        spans = self.f.filter("Routing: 021000021")
        assert any("021000021" in s.text for s in spans)

    def test_no_routing(self):
        spans = self.f.filter("No routing number here.")
        assert len(spans) == 0


# ---------------------------------------------------------------------------
# Date Filter
# ---------------------------------------------------------------------------

class TestDateFilter:
    def setup_method(self):
        self.f = DateFilter(_default_config(DateFilterConfig))

    def test_mm_dd_yyyy_slash(self):
        spans = self.f.filter("DOB: 01/15/1990")
        assert any("01/15/1990" in s.text for s in spans)

    def test_mm_dd_yyyy_dash(self):
        spans = self.f.filter("Date: 12-31-2000")
        assert any("12-31-2000" in s.text for s in spans)

    def test_iso_date(self):
        spans = self.f.filter("Admitted: 2023-07-04")
        assert any("2023-07-04" in s.text for s in spans)

    def test_month_dd_yyyy(self):
        spans = self.f.filter("Born on January 15, 1990.")
        assert len(spans) >= 1

    def test_no_date(self):
        spans = self.f.filter("No date here.")
        assert len(spans) == 0


# ---------------------------------------------------------------------------
# MAC Address Filter
# ---------------------------------------------------------------------------

class TestMACAddressFilter:
    def setup_method(self):
        self.f = MACAddressFilter(_default_config(MACAddressFilterConfig))

    def test_mac_colons(self):
        spans = self.f.filter("MAC: 00:1A:2B:3C:4D:5E")
        assert any("00:1A:2B:3C:4D:5E" in s.text for s in spans)

    def test_mac_dashes(self):
        spans = self.f.filter("MAC: 00-1A-2B-3C-4D-5E")
        assert any("00-1A-2B-3C-4D-5E" in s.text for s in spans)

    def test_no_mac(self):
        spans = self.f.filter("No MAC address here.")
        assert len(spans) == 0


# ---------------------------------------------------------------------------
# Currency Filter
# ---------------------------------------------------------------------------

class TestCurrencyFilter:
    def setup_method(self):
        self.f = CurrencyFilter(_default_config(CurrencyFilterConfig))

    def test_simple_dollar(self):
        spans = self.f.filter("Price: $100")
        assert any("$100" in s.text for s in spans)

    def test_dollar_with_cents(self):
        spans = self.f.filter("Total: $1,234.56")
        assert len(spans) >= 1

    def test_dollar_million(self):
        spans = self.f.filter("Revenue: $5 million")
        assert len(spans) >= 1

    def test_no_currency(self):
        spans = self.f.filter("No currency here.")
        assert len(spans) == 0


# ---------------------------------------------------------------------------
# Street Address Filter
# ---------------------------------------------------------------------------

class TestStreetAddressFilter:
    def setup_method(self):
        self.f = StreetAddressFilter(_default_config(StreetAddressFilterConfig))

    def test_street(self):
        spans = self.f.filter("Lives at 123 Main Street.")
        assert len(spans) >= 1

    def test_avenue(self):
        spans = self.f.filter("Office at 456 Oak Avenue.")
        assert len(spans) >= 1

    def test_no_address(self):
        spans = self.f.filter("No address here.")
        assert len(spans) == 0


# ---------------------------------------------------------------------------
# Tracking Number Filter
# ---------------------------------------------------------------------------

class TestTrackingNumberFilter:
    def setup_method(self):
        self.f = TrackingNumberFilter(_default_config(TrackingNumberFilterConfig))

    def test_ups(self):
        spans = self.f.filter("Track: 1Z999AA10123456784")
        assert len(spans) >= 1

    def test_usps_format(self):
        spans = self.f.filter("USPS: EA123456789US")
        assert len(spans) >= 1

    def test_no_tracking(self):
        spans = self.f.filter("No tracking number.")
        assert len(spans) == 0


# ---------------------------------------------------------------------------
# IBAN Code Filter
# ---------------------------------------------------------------------------

class TestIBANCodeFilter:
    def setup_method(self):
        self.f = IBANCodeFilter(_default_config(IBANCodeFilterConfig))

    def test_iban(self):
        spans = self.f.filter("IBAN: GB29NWBK60161331926819")
        assert any("GB29NWBK60161331926819" in s.text for s in spans)

    def test_no_iban(self):
        spans = self.f.filter("No IBAN here.")
        assert len(spans) == 0


# ---------------------------------------------------------------------------
# Passport Number Filter
# ---------------------------------------------------------------------------

class TestPassportNumberFilter:
    def setup_method(self):
        self.f = PassportNumberFilter(_default_config(PassportNumberFilterConfig))

    def test_us_passport(self):
        spans = self.f.filter("Passport: A12345678")
        assert any("A12345678" in s.text for s in spans)

    def test_no_passport(self):
        spans = self.f.filter("No passport number here.")
        assert len(spans) == 0


# ---------------------------------------------------------------------------
# Ignored terms
# ---------------------------------------------------------------------------

class TestIgnoredTerms:
    def test_ignored_email(self):
        config = EmailAddressFilterConfig(ignored=["noreply@example.com"])
        f = EmailAddressFilter(config)
        spans = f.filter("Email: noreply@example.com")
        assert len(spans) == 0

    def test_non_ignored_email(self):
        config = EmailAddressFilterConfig(ignored=["noreply@example.com"])
        f = EmailAddressFilter(config)
        spans = f.filter("Email: user@example.com")
        assert len(spans) == 1


# ---------------------------------------------------------------------------
# Filter Strategy
# ---------------------------------------------------------------------------

class TestFilterStrategyReplacements:
    def test_redact(self):
        s = FilterStrategy(strategy="REDACT")
        assert s.get_replacement("email-address", "test@example.com") == "{{{REDACTED-email-address}}}"

    def test_mask(self):
        s = FilterStrategy(strategy="MASK", mask_character="*")
        assert s.get_replacement("ssn", "123-45-6789") == "*" * 11

    def test_static_replace(self):
        s = FilterStrategy(strategy="STATIC_REPLACE", static_replacement="[HIDDEN]")
        assert s.get_replacement("ssn", "123-45-6789") == "[HIDDEN]"

    def test_hash_sha256(self):
        import hashlib
        s = FilterStrategy(strategy="HASH_SHA256_REPLACE")
        token = "test@example.com"
        expected = hashlib.sha256(token.encode()).hexdigest()
        assert s.get_replacement("email-address", token) == expected

    def test_last_4(self):
        s = FilterStrategy(strategy="LAST_4")
        assert s.get_replacement("credit-card", "4111111111111111") == "************1111"

    def test_same(self):
        s = FilterStrategy(strategy="SAME")
        assert s.get_replacement("email-address", "test@example.com") == "test@example.com"


# ---------------------------------------------------------------------------
# SHIFT_DATE Strategy
# ---------------------------------------------------------------------------

class TestShiftDateStrategy:
    def test_shift_days_iso(self):
        s = FilterStrategy(strategy="SHIFT_DATE", shift_days=10)
        assert s.get_replacement("date", "2023-07-04") == "2023-07-14"

    def test_shift_days_mmddyyyy_slash(self):
        s = FilterStrategy(strategy="SHIFT_DATE", shift_days=5)
        assert s.get_replacement("date", "01/15/1990") == "01/20/1990"

    def test_shift_days_mmddyyyy_dash(self):
        s = FilterStrategy(strategy="SHIFT_DATE", shift_days=1)
        assert s.get_replacement("date", "12-31-2000") == "01-01-2001"

    def test_shift_months_iso(self):
        s = FilterStrategy(strategy="SHIFT_DATE", shift_months=3)
        assert s.get_replacement("date", "2020-01-15") == "2020-04-15"

    def test_shift_years_iso(self):
        s = FilterStrategy(strategy="SHIFT_DATE", shift_years=2)
        assert s.get_replacement("date", "2020-06-01") == "2022-06-01"

    def test_shift_negative_days_iso(self):
        s = FilterStrategy(strategy="SHIFT_DATE", shift_days=-10)
        assert s.get_replacement("date", "2023-01-01") == "2022-12-22"

    def test_shift_month_name_format(self):
        s = FilterStrategy(strategy="SHIFT_DATE", shift_days=1)
        result = s.get_replacement("date", "January 15, 1990")
        assert result == "January 16, 1990"

    def test_shift_dd_month_yyyy_format(self):
        s = FilterStrategy(strategy="SHIFT_DATE", shift_days=5)
        result = s.get_replacement("date", "15 January 1990")
        assert result == "20 January 1990"

    def test_shift_end_of_month_clamped(self):
        # Shifting Jan 31 by one month → Feb 28 (non-leap) or Feb 29 (leap)
        s = FilterStrategy(strategy="SHIFT_DATE", shift_months=1)
        result = s.get_replacement("date", "2023-01-31")
        assert result == "2023-02-28"

    def test_shift_months_year_boundary(self):
        s = FilterStrategy(strategy="SHIFT_DATE", shift_months=3)
        assert s.get_replacement("date", "2020-11-15") == "2021-02-15"

    def test_from_dict_shift_date(self):
        data = {"strategy": "SHIFT_DATE", "shiftYears": 1, "shiftMonths": 2, "shiftDays": 3}
        s = FilterStrategy.from_dict(data)
        assert s.strategy == "SHIFT_DATE"
        assert s.shift_years == 1
        assert s.shift_months == 2
        assert s.shift_days == 3

    def test_to_dict_includes_shift_fields(self):
        s = FilterStrategy(strategy="SHIFT_DATE", shift_years=1, shift_months=2, shift_days=3)
        d = s.to_dict()
        assert d["strategy"] == "SHIFT_DATE"
        assert d["shiftYears"] == 1
        assert d["shiftMonths"] == 2
        assert d["shiftDays"] == 3

    def test_policy_json_shift_date(self):
        from phileas.policy.policy import Policy
        policy_json = json.dumps({
            "name": "test",
            "identifiers": {
                "date": {
                    "dateFilterStrategies": [
                        {"strategy": "SHIFT_DATE", "shiftYears": 0, "shiftMonths": 0, "shiftDays": 30}
                    ]
                }
            },
        })
        policy = Policy.from_json(policy_json)
        strategy = policy.identifiers.date.date_filter_strategies[0]
        assert strategy.strategy == "SHIFT_DATE"
        assert strategy.shift_days == 30

    def test_date_filter_uses_shift_date_strategy(self):
        from phileas.filters.date_filter import DateFilter
        from phileas.policy.identifiers import DateFilterConfig
        strategy = FilterStrategy(strategy="SHIFT_DATE", shift_days=10)
        config = DateFilterConfig(date_filter_strategies=[strategy])
        f = DateFilter(config)
        spans = f.filter("DOB: 2020-01-01")
        assert len(spans) == 1
        assert spans[0].replacement == "2020-01-11"

    def test_unrecognized_date_token_returned_unchanged(self):
        s = FilterStrategy(strategy="SHIFT_DATE", shift_days=5)
        assert s.get_replacement("date", "not-a-date") == "not-a-date"


# ---------------------------------------------------------------------------
# Ph-Eye Filter
# ---------------------------------------------------------------------------

class TestPhEyeFilter:
    def _make_filter(self, **kwargs):
        config = PhEyeFilterConfig(endpoint="http://pheye:8080", **kwargs)
        return PhEyeFilter(config)

    def _mock_response(self, spans_data):
        """Return a context manager that yields a mock HTTP response."""
        import io
        import unittest.mock as mock

        body = json.dumps(spans_data).encode("utf-8")
        mock_resp = mock.MagicMock()
        mock_resp.read.return_value = body
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = mock.MagicMock(return_value=False)
        return mock_resp

    def test_no_endpoint_returns_empty(self):
        config = PhEyeFilterConfig(endpoint="")
        f = PhEyeFilter(config)
        spans = f.filter("John Smith was here.")
        assert spans == []

    def test_person_span_returned(self):
        import unittest.mock as mock
        f = self._make_filter(labels=["PERSON"])
        response_data = [{"start": 0, "end": 10, "label": "PERSON", "text": "John Smith", "score": 0.95}]
        with mock.patch("urllib.request.urlopen", return_value=self._mock_response(response_data)):
            spans = f.filter("John Smith was here.")
        assert len(spans) == 1
        assert spans[0].text == "John Smith"
        assert spans[0].filter_type == "person"
        assert spans[0].confidence == 0.95

    def test_label_filtered_out(self):
        import unittest.mock as mock
        f = self._make_filter(labels=["PERSON"])
        response_data = [{"start": 5, "end": 12, "label": "ORG", "text": "Acme Inc", "score": 0.9}]
        with mock.patch("urllib.request.urlopen", return_value=self._mock_response(response_data)):
            spans = f.filter("At Acme Inc today.")
        assert len(spans) == 0

    def test_threshold_filters_low_score(self):
        import unittest.mock as mock
        f = self._make_filter(labels=["PERSON"], thresholds={"PERSON": 0.9})
        response_data = [{"start": 0, "end": 10, "label": "PERSON", "text": "John Smith", "score": 0.75}]
        with mock.patch("urllib.request.urlopen", return_value=self._mock_response(response_data)):
            spans = f.filter("John Smith was here.")
        assert len(spans) == 0

    def test_threshold_passes_high_score(self):
        import unittest.mock as mock
        f = self._make_filter(labels=["PERSON"], thresholds={"PERSON": 0.9})
        response_data = [{"start": 0, "end": 10, "label": "PERSON", "text": "John Smith", "score": 0.95}]
        with mock.patch("urllib.request.urlopen", return_value=self._mock_response(response_data)):
            spans = f.filter("John Smith was here.")
        assert len(spans) == 1

    def test_ignored_term_excluded(self):
        import unittest.mock as mock
        f = self._make_filter(labels=["PERSON"], ignored=["John Smith"])
        response_data = [{"start": 0, "end": 10, "label": "PERSON", "text": "John Smith", "score": 0.95}]
        with mock.patch("urllib.request.urlopen", return_value=self._mock_response(response_data)):
            spans = f.filter("John Smith was here.")
        assert len(spans) == 0

    def test_default_redact_replacement(self):
        import unittest.mock as mock
        f = self._make_filter(labels=["PERSON"])
        response_data = [{"start": 0, "end": 10, "label": "PERSON", "text": "John Smith", "score": 0.95}]
        with mock.patch("urllib.request.urlopen", return_value=self._mock_response(response_data)):
            spans = f.filter("John Smith was here.")
        assert spans[0].replacement == "{{{REDACTED-person}}}"

    def test_non_person_label_filter_type(self):
        import unittest.mock as mock
        f = self._make_filter(labels=["ORG"])
        response_data = [{"start": 0, "end": 8, "label": "ORG", "text": "Acme Inc", "score": 0.9}]
        with mock.patch("urllib.request.urlopen", return_value=self._mock_response(response_data)):
            spans = f.filter("Acme Inc is hiring.")
        assert len(spans) == 1
        assert spans[0].filter_type == "org"

    def test_bearer_token_sent(self):
        import unittest.mock as mock
        config = PhEyeFilterConfig(endpoint="http://pheye:8080", bearer_token="secret-token")
        f = PhEyeFilter(config)
        response_data = []
        captured_req = {}

        def fake_urlopen(req, timeout=None):
            captured_req["headers"] = dict(req.headers)
            return self._mock_response(response_data)

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            f.filter("Some text.")

        assert "Authorization" in captured_req["headers"]
        assert captured_req["headers"]["Authorization"] == "Bearer secret-token"

    def test_url_error_raises_ioerror(self):
        import unittest.mock as mock
        import urllib.error
        f = self._make_filter()
        with mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("connection refused")):
            with pytest.raises(IOError):
                f.filter("John Smith was here.")

    def test_policy_json_ph_eye(self):
        from phileas.policy.policy import Policy
        policy_json = json.dumps({
            "name": "test",
            "identifiers": {
                "phEye": [
                    {
                        "endpoint": "http://pheye:8080",
                        "labels": ["PERSON"],
                        "phEyeFilterStrategies": [{"strategy": "REDACT", "redactionFormat": "{{{REDACTED-%t}}}"}],
                    }
                ],
            },
        })
        policy = Policy.from_json(policy_json)
        assert len(policy.identifiers.ph_eye) == 1
        assert policy.identifiers.ph_eye[0].endpoint == "http://pheye:8080"
        assert policy.identifiers.ph_eye[0].labels == ["PERSON"]

    def test_identifiers_to_dict_roundtrip(self):
        from phileas.policy.identifiers import Identifiers
        ids = Identifiers()
        ids.ph_eye.append(PhEyeFilterConfig(
            endpoint="http://pheye:8080",
            labels=["PERSON"],
            bearer_token="tok",
        ))
        d = ids.to_dict()
        assert "phEye" in d
        assert isinstance(d["phEye"], list)
        assert d["phEye"][0]["endpoint"] == "http://pheye:8080"
        assert d["phEye"][0]["bearerToken"] == "tok"

    def test_multiple_ph_eye_filters(self):
        from phileas.policy.policy import Policy
        policy_json = json.dumps({
            "name": "multi-pheye",
            "identifiers": {
                "phEye": [
                    {"endpoint": "http://pheye1:8080", "labels": ["PERSON"]},
                    {"endpoint": "http://pheye2:8080", "labels": ["ORG"]},
                ],
            },
        })
        policy = Policy.from_json(policy_json)
        assert len(policy.identifiers.ph_eye) == 2
        assert policy.identifiers.ph_eye[0].endpoint == "http://pheye1:8080"
        assert policy.identifiers.ph_eye[1].endpoint == "http://pheye2:8080"
        assert policy.identifiers.ph_eye[0].labels == ["PERSON"]
        assert policy.identifiers.ph_eye[1].labels == ["ORG"]

    def test_ph_eye_backward_compat_single_dict(self):
        """Single dict (legacy format) should still be parsed as a list with one item."""
        from phileas.policy.policy import Policy
        policy_json = json.dumps({
            "name": "legacy",
            "identifiers": {
                "phEye": {
                    "endpoint": "http://pheye:8080",
                    "labels": ["PERSON"],
                },
            },
        })
        policy = Policy.from_json(policy_json)
        assert len(policy.identifiers.ph_eye) == 1
        assert policy.identifiers.ph_eye[0].endpoint == "http://pheye:8080"
