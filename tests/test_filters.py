"""Tests for individual PII/PHI filters."""

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
        assert any("http://example.com" in s.text for s in spans)

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
        spans = self.f.filter("Bitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf Na")
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
