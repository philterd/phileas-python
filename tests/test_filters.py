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

"""Tests for detection filters (detect-only interface)."""

from phileas.filters.age_filter import AgeFilter
from phileas.filters.credit_card_filter import CreditCardFilter
from phileas.filters.date_filter import DateFilter
from phileas.filters.dictionary_filter import DictionaryFilter
from phileas.filters.email_address_filter import EmailAddressFilter
from phileas.filters.pattern_filter import PatternFilter
from phileas.filters.ssn_filter import SSNFilter
from phileas.filters.zip_code_filter import ZipCodeFilter


class TestDetection:
    def test_detect_returns_spans_without_replacement(self):
        spans = EmailAddressFilter().detect("Contact a@b.com please.")
        assert len(spans) == 1
        span = spans[0]
        assert span.text == "a@b.com"
        assert span.filter_type == "email-address"
        assert span.replacement == ""  # service fills this in later
        assert span.character_start == len("Contact ")

    def test_ssn(self):
        spans = SSNFilter().detect("SSN 123-45-6789.")
        assert any(s.text == "123-45-6789" for s in spans)

    def test_age(self):
        assert AgeFilter().detect("She is 45 years old.")

    def test_date(self):
        spans = DateFilter().detect("DOB 2020-01-05.")
        assert spans[0].text == "2020-01-05"

    def test_zip(self):
        spans = ZipCodeFilter().detect("ZIP 90210 here.")
        assert any(s.text == "90210" for s in spans)


class TestCreditCardLuhn:
    def test_no_luhn_by_default(self):
        spans = CreditCardFilter().detect("Card 4111111111111112")  # fails luhn
        assert len(spans) == 1

    def test_luhn_filters_invalid(self):
        valid = CreditCardFilter({"luhnCheck": True}).detect("Card 4111111111111111")
        invalid = CreditCardFilter({"luhnCheck": True}).detect("Card 4111111111111112")
        assert len(valid) == 1
        assert len(invalid) == 0


class TestDictionaryFilter:
    def test_terms_detected(self):
        f = DictionaryFilter({"classification": "names", "terms": ["Acme", "Globex"]})
        spans = f.detect("Acme and Globex and Initech.")
        found = {s.text for s in spans}
        assert found == {"Acme", "Globex"}
        assert all(s.filter_type == "names" for s in spans)

    def test_empty_terms(self):
        assert DictionaryFilter({"terms": []}).detect("anything") == []


class TestPatternFilter:
    def test_custom_identifier(self):
        f = PatternFilter({"classification": "MRN", "pattern": r"MRN-\d{6}"})
        spans = f.detect("Record MRN-123456 today.")
        assert spans[0].text == "MRN-123456"
        assert spans[0].filter_type == "MRN"

    def test_case_insensitive(self):
        f = PatternFilter({"classification": "X", "pattern": r"abc", "caseSensitive": False})
        assert f.detect("ABC") and f.detect("abc")

    def test_group_number(self):
        f = PatternFilter({"classification": "G", "pattern": r"id=(\d+)", "groupNumber": 1})
        spans = f.detect("user id=42 here")
        assert spans[0].text == "42"
