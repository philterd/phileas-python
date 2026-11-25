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

"""Span confidences match the canonical table in philterd/phileas-conformance#7,
which Phileas (Java) and phileas-dotnet use (issue #102)."""

import pytest

from phileas.filters.age_filter import AgeFilter
from phileas.filters.bank_routing_number_filter import BankRoutingNumberFilter
from phileas.filters.bitcoin_address_filter import BitcoinAddressFilter
from phileas.filters.credit_card_filter import CreditCardFilter
from phileas.filters.currency_filter import CurrencyFilter
from phileas.filters.date_filter import DateFilter
from phileas.filters.dictionary_filter import DictionaryFilter
from phileas.filters.drivers_license_filter import DriversLicenseFilter
from phileas.filters.ein_filter import EINFilter
from phileas.filters.email_address_filter import EmailAddressFilter
from phileas.filters.iban_code_filter import IBANCodeFilter
from phileas.filters.ip_address_filter import IPAddressFilter
from phileas.filters.mac_address_filter import MACAddressFilter
from phileas.filters.passport_number_filter import PassportNumberFilter
from phileas.filters.pattern_filter import PatternFilter
from phileas.filters.ssn_filter import SSNFilter
from phileas.filters.street_address_filter import StreetAddressFilter
from phileas.filters.tracking_number_filter import TrackingNumberFilter
from phileas.filters.url_filter import URLFilter
from phileas.filters.vin_filter import VINFilter
from phileas.filters.zip_code_filter import ZipCodeFilter
from phileas.policy.policy import Policy
from phileas.services.filter_service import FilterService


CASES = [
    (AgeFilter, "47 years old", 0.9),
    (BankRoutingNumberFilter, "111000025", 0.95),
    (BitcoinAddressFilter, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 0.9),
    (CreditCardFilter, "4111111111111111", 0.9),
    (CurrencyFilter, "$1,234.56", 0.8),
    (DateFilter, "2026-03-15", 0.75),
    (DateFilter, "03-15-2026", 0.75),
    (DriversLicenseFilter, "A1234567", 0.5),
    (EINFilter, "12-3456789", 0.95),
    (EmailAddressFilter, "jane@example.com", 0.9),
    (IBANCodeFilter, "GB82WEST12345698765432", 0.9),
    (IPAddressFilter, "192.0.2.10", 0.9),
    (IPAddressFilter, "2001:db8::1", 0.9),
    (MACAddressFilter, "00:1A:2B:3C:4D:5E", 0.9),
    (PassportNumberFilter, "912345678", 0.55),
    (PassportNumberFilter, "C03005988", 0.75),
    (SSNFilter, "123-45-6789", 0.9),
    (StreetAddressFilter, "123 Main Street", 0.85),
    (TrackingNumberFilter, "1Z999AA10123456784", 0.9),
    (TrackingNumberFilter, "123456789012", 0.75),
    (TrackingNumberFilter, "9400100000000000000000", 0.9),
    (TrackingNumberFilter, "RA123456789US", 0.9),
    (URLFilter, "https://www.example.com/path", 0.8),
    (VINFilter, "1HGCM82633A004352", 0.9),
    (ZipCodeFilter, "21201", 0.5),
]


@pytest.mark.parametrize("filter_class,value,confidence", CASES)
def test_rules_based_filters_report_the_canonical_confidence(filter_class, value, confidence):
    spans = filter_class().detect(value)
    assert [(s.text, s.confidence) for s in spans] == [(value, confidence)]


def test_custom_identifier_confidence():
    spans = PatternFilter({"pattern": r"CASE-\d+", "classification": "case"}).detect("CASE-4821")
    assert [(s.text, s.confidence) for s in spans] == [("CASE-4821", 0.9)]


def test_dictionary_confidence():
    spans = DictionaryFilter({"classification": "names", "terms": ["Jane"]}).detect("Jane")
    assert [(s.text, s.confidence) for s in spans] == [("Jane", 1.0)]


@pytest.mark.parametrize(
    "text,confidence",
    [
        ("card 4111111111111111 on file", 0.9),
        ("ref-4111111111111111 on file", 0.6),
        ("card 4111111111111111-x on file", 0.6),
        ("ref-4111111111111111-x on file", 0.5),
    ],
)
def test_credit_card_hyphen_lowers_the_confidence(text, confidence):
    spans = CreditCardFilter().detect(text)
    assert [(s.text, s.confidence) for s in spans] == [("4111111111111111", confidence)]


def _ssn_policy(condition):
    return Policy.from_dict({"name": "t", "identifiers": {"ssn": {"ssnFilterStrategies": [
        {"strategy": "STATIC_REPLACE", "staticReplacement": "MATCHED", "condition": condition},
        {"strategy": "REDACT"},
    ]}}})


@pytest.mark.parametrize("condition,expected", [
    ("confidence == 0.9", "ssn MATCHED"),
    ("confidence == 1.0", "ssn {{{REDACTED-ssn}}}"),
])
def test_ssn_confidence_condition_matches_java_and_dotnet(condition, expected):
    result = FilterService().filter(_ssn_policy(condition), "c", "d", "ssn 123-45-6789")
    assert result.filtered_text == expected
