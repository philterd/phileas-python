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

"""Characterization tests for the CreditCardFilter detection filter."""

import pytest

from phileas.filters.credit_card_filter import CreditCardFilter


# (label, number) pairs covering every brand regex in the filter.
POSITIVE_NUMBERS = [
    ("visa_16", "4111111111111111"),
    ("visa_13", "4222222222222"),
    ("mastercard_51", "5105105105105100"),
    ("mastercard_55", "5555555555554444"),
    ("mastercard_2221", "2221000000000009"),
    ("mastercard_2720", "2720990000000005"),
    ("amex_34", "340000000000009"),
    ("amex_37", "378282246310005"),
    ("discover_6011", "6011000000000004"),
    ("discover_65", "6500000000000002"),
    ("diners_30", "30000000000004"),
    ("diners_36", "36000000000008"),
    ("diners_38", "38000000000006"),
    ("jcb_2131", "213100000000000"),
    ("jcb_1800", "180000000000000"),
    ("jcb_35", "3530111333300000"),
]


class TestPositiveBrands:
    @pytest.mark.parametrize("label,number", POSITIVE_NUMBERS)
    def test_brand_detected(self, label, number):
        spans = CreditCardFilter().detect(number)
        assert len(spans) == 1
        assert spans[0].text == number

    @pytest.mark.parametrize("label,number", POSITIVE_NUMBERS)
    def test_brand_filter_type(self, label, number):
        spans = CreditCardFilter().detect(number)
        assert spans[0].filter_type == "credit-card"

    @pytest.mark.parametrize("label,number", POSITIVE_NUMBERS)
    def test_brand_confidence_and_replacement(self, label, number):
        span = CreditCardFilter().detect(number)[0]
        assert span.confidence == 1.0
        assert span.replacement == ""

    @pytest.mark.parametrize("label,number", POSITIVE_NUMBERS)
    def test_brand_offsets(self, label, number):
        prefix = "Card: "
        text = f"{prefix}{number} done"
        span = CreditCardFilter().detect(text)[0]
        assert span.character_start == len(prefix)
        assert span.character_end == len(prefix) + len(number)
        assert text[span.character_start:span.character_end] == number


class TestEmbeddedInText:
    def test_detected_in_sentence(self):
        text = "Please bill my card 4111111111111111 today."
        spans = CreditCardFilter().detect(text)
        assert len(spans) == 1
        assert spans[0].text == "4111111111111111"

    def test_amex_in_sentence(self):
        text = "My amex is 378282246310005 ok"
        spans = CreditCardFilter().detect(text)
        assert len(spans) == 1
        assert spans[0].text == "378282246310005"

    def test_multiple_cards(self):
        text = "Cards 4111111111111111 and 5555555555554444."
        texts = {s.text for s in CreditCardFilter().detect(text)}
        assert "4111111111111111" in texts
        assert "5555555555554444" in texts

    def test_default_context(self):
        spans = CreditCardFilter().detect("4111111111111111")
        assert spans[0].context == "default"

    def test_explicit_context(self):
        spans = CreditCardFilter().detect("4111111111111111", context="ctx")
        assert spans[0].context == "ctx"


# Strings that must NOT be detected as credit cards.
NEGATIVE_STRINGS = [
    ("too_short", "123"),
    ("four_digits", "4111"),
    ("twenty_digits", "12345678901234567890"),
    ("non_numeric", "not a number"),
    ("visa_too_long", "411111111111111111111"),
    ("empty", ""),
    ("words", "the quick brown fox"),
    ("eleven_digits", "12345678901"),
]


class TestNegatives:
    @pytest.mark.parametrize("label,value", NEGATIVE_STRINGS)
    def test_not_detected(self, label, value):
        assert CreditCardFilter().detect(value) == []

    def test_visa_with_extra_leading_digits_not_matched(self):
        # A 21-digit run has no valid card boundary -> no match.
        assert CreditCardFilter().detect("999411111111111111199") == []


class TestLuhnCheck:
    def test_default_keeps_luhn_invalid(self):
        # Without luhnCheck the structurally-valid-but-luhn-invalid number stays.
        spans = CreditCardFilter().detect("4111111111111112")
        assert len(spans) == 1

    def test_luhn_check_drops_invalid(self):
        spans = CreditCardFilter({"luhnCheck": True}).detect("4111111111111112")
        assert spans == []

    def test_luhn_check_keeps_valid_visa(self):
        spans = CreditCardFilter({"luhnCheck": True}).detect("4111111111111111")
        assert len(spans) == 1
        assert spans[0].text == "4111111111111111"

    def test_luhn_check_keeps_valid_amex(self):
        spans = CreditCardFilter({"luhnCheck": True}).detect("378282246310005")
        assert len(spans) == 1

    @pytest.mark.parametrize(
        "number",
        [
            "4111111111111111",
            "5105105105105100",
            "5555555555554444",
            "2221000000000009",
            "340000000000009",
            "6011000000000004",
            "30000000000004",
            "3530111333300000",
        ],
    )
    def test_luhn_check_keeps_known_valid(self, number):
        spans = CreditCardFilter({"luhnCheck": True}).detect(number)
        assert len(spans) == 1
        assert spans[0].text == number

    @pytest.mark.parametrize(
        "number",
        [
            # These pass the brand regexes but fail the Luhn algorithm.
            "2720990000000005",
            "213100000000000",
            "180000000000000",
        ],
    )
    def test_luhn_check_drops_known_invalid(self, number):
        # No luhnCheck: detected.
        assert len(CreditCardFilter().detect(number)) == 1
        # With luhnCheck: dropped.
        assert CreditCardFilter({"luhnCheck": True}).detect(number) == []

    def test_luhn_false_explicit_keeps_invalid(self):
        spans = CreditCardFilter({"luhnCheck": False}).detect("4111111111111112")
        assert len(spans) == 1


class TestConfigConstruction:
    def test_none_config(self):
        assert CreditCardFilter(None).config == {}

    def test_empty_config(self):
        assert CreditCardFilter({}).config == {}

    def test_default_construction(self):
        spans = CreditCardFilter().detect("4111111111111111")
        assert len(spans) == 1


class TestSeparators:
    """Cards written in groups, the way they are printed and typed."""

    @pytest.mark.parametrize(
        "value",
        [
            "4111 1111 1111 1111",      # Visa, spaces
            "4111-1111-1111-1111",      # Visa, hyphens
            "4111-1111 1111-1111",      # mixed
            "5500 0000 0000 0004",      # MasterCard
            "5500-0000-0000-0004",
            "3782 822463 10005",        # Amex, 4-6-5 grouping
            "6011-1111-1111-1117",      # Discover
            "3056-930902-5904",         # Diners Club
            "3530 1113 3330 0000",      # JCB
        ],
    )
    def test_separated_card_detected(self, value):
        spans = CreditCardFilter().detect(f"Card {value} on file")
        assert [s.text for s in spans] == [value]

    def test_offsets_cover_the_whole_number(self):
        text = "Card: 4111 1111 1111 1111."
        span = CreditCardFilter().detect(text)[0]
        assert text[span.character_start:span.character_end] == "4111 1111 1111 1111"

    def test_luhn_check_applies_to_separated_numbers(self):
        good, bad = "4111 1111 1111 1111", "4111 1111 1111 1112"
        assert [s.text for s in CreditCardFilter({"luhnCheck": True}).detect(good)] == [good]
        assert CreditCardFilter({"luhnCheck": True}).detect(bad) == []
        # Without the check the mistyped number is still card-shaped.
        assert [s.text for s in CreditCardFilter().detect(bad)] == [bad]

    def test_redacted_end_to_end(self):
        from phileas.policy.policy import Policy
        from phileas.services.filter_service import FilterService

        policy = Policy.from_dict({"name": "t", "identifiers": {"creditCard": {
            "creditCardFilterStrategies": [{"strategy": "REDACT"}]}}})
        r = FilterService().filter(policy, "c", "d", "Card 4111 1111 1111 1111 ok.")
        assert "4111 1111 1111 1111" not in r.filtered_text
        assert "{{{REDACTED-credit-card}}}" in r.filtered_text


class TestSeparatorsDoNotWiden:
    """A digit run of card length is only claimed when it carries an issuer prefix."""

    @pytest.mark.parametrize(
        "value",
        [
            "1234 5678 9012 3456",   # 16 digits, no issuer prefix
            "9999 9999 9999 9999",
            "1234567890123",         # 13 digits, no issuer prefix
            "0000-0000-0000-0000",
        ],
    )
    def test_unrelated_digit_run_not_claimed(self, value):
        assert CreditCardFilter().detect(f"Ref {value} here") == []

    @pytest.mark.parametrize(
        "text",
        [
            "call 555-123-4567 now",     # phone
            "on 2026-01-15 we met",      # date
            "id 20255512349999 end",     # long digit run
            "ssn 123-45-6789 here",
        ],
    )
    def test_other_identifiers_not_claimed(self, text):
        assert CreditCardFilter().detect(text) == []

    def test_separator_must_be_single(self):
        # One space or hyphen between digits; a wider gap is two numbers, not one.
        assert CreditCardFilter().detect("4111  1111  1111  1111") == []

    def test_dots_are_not_separators(self):
        assert CreditCardFilter().detect("4111.1111.1111.1111") == []

    def test_adjacent_cards_are_separate_spans(self):
        text = "4111 1111 1111 1111 5500 0000 0000 0004"
        assert [s.text for s in CreditCardFilter().detect(text)] == [
            "4111 1111 1111 1111", "5500 0000 0000 0004"
        ]

    def test_over_long_separated_run_claims_its_card_length_head(self):
        # Characterization: a separated run longer than a card yields its first 16
        # digits, because the space after them is a word boundary. The contiguous
        # form has no such boundary and yields nothing. Java's generic pattern
        # behaves the same way.
        assert [s.text for s in CreditCardFilter().detect("4111 1111 1111 1111 1111")] == [
            "4111 1111 1111 1111"
        ]
        assert CreditCardFilter().detect("41111111111111111111") == []

    def test_card_beside_other_digits_keeps_its_own_bounds(self):
        # Regression: an earlier version consumed "89-4258428518601" as one
        # candidate, failed it, and lost the 13-digit Visa inside it.
        assert [s.text for s in CreditCardFilter().detect("89-4258428518601")] == [
            "4258428518601"
        ]

    def test_separated_card_beside_other_digits(self):
        assert [s.text for s in CreditCardFilter().detect("89-4111 1111 1111 1111")] == [
            "4111 1111 1111 1111"
        ]

    def test_one_span_per_card(self):
        # Overlapping candidate slices are resolved, so a card is reported once.
        text = "Card 4111 1111 1111 1111 paid"
        assert len(CreditCardFilter().detect(text)) == 1
