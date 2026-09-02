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

import pytest

from phileas.filters.iban_code_filter import IBANCodeFilter


FILTER_TYPE = "iban-code"


@pytest.fixture
def filt():
    return IBANCodeFilter()


# ---------------------------------------------------------------------------
# Positive cases
# ---------------------------------------------------------------------------

REAL_IBANS = [
    "GB29NWBK60161331926819",
    "DE89370400440532013000",
    "FR1420041010050500013M02606",
    "NL91ABNA0417164300",
    "ES9121000418450200051332",
    "CH9300762011623852957",
]


@pytest.mark.parametrize("iban", REAL_IBANS)
def test_detects_real_ibans(filt, iban):
    spans = filt.detect(iban)
    assert len(spans) == 1
    assert spans[0].text == iban


@pytest.mark.parametrize("iban", REAL_IBANS)
def test_span_attributes(filt, iban):
    span = filt.detect(iban)[0]
    assert span.filter_type == FILTER_TYPE
    assert span.character_start == 0
    assert span.character_end == len(iban)
    assert span.confidence == 1.0
    # detect() never sets a replacement
    assert span.replacement == ""


def test_minimum_length_match(filt):
    # 2 letters + 2 digits + 4 alnum + 7 digits = 15 chars is the minimum.
    iban = "GB29ABCD1234567"
    assert len(iban) == 15
    spans = filt.detect(iban)
    assert len(spans) == 1
    assert spans[0].text == iban


def test_maximum_length_match(filt):
    # 15 mandatory chars + 16 optional trailing alnum = 31 chars maximum.
    iban = "GB29ABCD1234567" + "A" * 16
    assert len(iban) == 31
    spans = filt.detect(iban)
    assert len(spans) == 1
    assert spans[0].text == iban


def test_digits_allowed_in_bban_letters_position(filt):
    # The fifth-through-eighth chars are [A-Z0-9]; an all-digit segment is fine.
    iban = "FR1420041010050500013M02606"
    spans = filt.detect(iban)
    assert len(spans) == 1
    assert spans[0].text == iban


def test_iban_in_sentence(filt):
    text = "Wire to IBAN GB29NWBK60161331926819 by Friday."
    spans = filt.detect(text)
    assert len(spans) == 1
    assert spans[0].text == "GB29NWBK60161331926819"
    assert text[spans[0].character_start : spans[0].character_end] == spans[0].text


def test_offsets_in_sentence(filt):
    iban = "DE89370400440532013000"
    text = "abc " + iban + " def"
    spans = filt.detect(text)
    assert len(spans) == 1
    assert spans[0].character_start == 4
    assert spans[0].character_end == 4 + len(iban)
    assert spans[0].text == iban


def test_multiple_ibans(filt):
    a = "GB29NWBK60161331926819"
    b = "DE89370400440532013000"
    text = f"{a} and {b}"
    spans = filt.detect(text)
    found = {s.text for s in spans}
    assert found == {a, b}
    assert len(spans) == 2


def test_returns_empty_list_when_none(filt):
    result = filt.detect("no iban here")
    assert isinstance(result, list)
    assert result == []


def test_context_passed_through(filt):
    iban = "GB29NWBK60161331926819"
    spans = filt.detect(iban, context="ctx-name")
    assert len(spans) == 1
    assert spans[0].context == "ctx-name"


def test_default_config_none_behaves_like_default():
    f = IBANCodeFilter(None)
    iban = "GB29NWBK60161331926819"
    assert len(f.detect(iban)) == 1


def test_empty_config_dict():
    f = IBANCodeFilter({})
    iban = "GB29NWBK60161331926819"
    assert len(f.detect(iban)) == 1


# ---------------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------------

NEGATIVE_CASES = [
    # empty / plain text
    "",
    "no iban here",
    "1234567890",
    # lowercase country code (pattern requires [A-Z]{2})
    "gb29nwbk60161331926819",
    # only one letter country code
    "G29NWBK60161331926819",
    # missing the leading country code entirely
    "29NWBK60161331926819",
    "60161331926819",
    # check digits not digits
    "GBxxNWBK60161331926819",
    # only one check digit (shifts structure, fails)
    "GB2NWBK60161331926819",
    # mandatory 7-digit block contains a letter
    "GB29ABCD123456X",
    # the 4-char alnum block followed by letters where digits are required
    "GB291234ABCDEFG",
    # one char shorter than the 15-char minimum
    "GB29ABCD123456",
    # lowercase letters in the BBAN body
    "GB29abcd1234567",
    # separator breaking the run
    "GB29NW-K60161331926819",
]


@pytest.mark.parametrize("text", NEGATIVE_CASES)
def test_negative_no_detection(filt, text):
    assert filt.detect(text) == []


def test_too_long_run_not_detected(filt):
    # 17 trailing optional chars exceeds the {0,16} cap; because the 32nd char
    # is still a word char there is no word boundary, so nothing matches.
    iban = "GB29ABCD1234567" + "A" * 17
    assert filt.detect(iban) == []


def test_glued_to_letters_not_matched(filt):
    # A valid IBAN glued to letters on both sides has no word boundary.
    iban = "GB29NWBK60161331926819"
    text = "xxx" + iban + "yyy"
    assert filt.detect(text) == []


def test_leading_letters_break_country_code(filt):
    iban = "GB29NWBK60161331926819"
    assert filt.detect("xxx" + iban) == []


# ---------------------------------------------------------------------------
# The printed form: groups of four (issue #63)
# ---------------------------------------------------------------------------

SPACED_IBANS = [
    "GB82 WEST 1234 5698 7654 32",
    "GB29 NWBK 6016 1331 9268 19",
    "DE89 3704 0044 0532 0130 00",
    "NL91 ABNA 0417 1643 00",
    "ES91 2100 0418 4502 0005 1332",
    "CH93 0076 2011 6238 5295 7",
    "FR14 2004 1010 0505 0001 3M02 606",
]


@pytest.mark.parametrize("iban", SPACED_IBANS)
def test_detects_spaced_ibans(filt, iban):
    assert [s.text for s in filt.detect(iban)] == [iban]


def test_spaced_iban_offsets(filt):
    text = "Pay to GB82 WEST 1234 5698 7654 32 today."
    span = filt.detect(text)[0]
    assert text[span.character_start:span.character_end] == "GB82 WEST 1234 5698 7654 32"


def test_two_spaced_ibans(filt):
    text = "GB82 WEST 1234 5698 7654 32 and DE89 3704 0044 0532 0130 00"
    assert [s.text for s in filt.detect(text)] == [
        "GB82 WEST 1234 5698 7654 32", "DE89 3704 0044 0532 0130 00"
    ]


def test_spaced_iban_redacted_end_to_end():
    from phileas.policy.policy import Policy
    from phileas.services.filter_service import FilterService

    policy = Policy.from_dict({"name": "t", "identifiers": {"ibanCode": {
        "ibanCodeFilterStrategies": [{"strategy": "REDACT"}]}}})
    r = FilterService().filter(policy, "c", "d", "Pay GB82 WEST 1234 5698 7654 32 now.")
    assert "GB82 WEST 1234 5698 7654 32" not in r.filtered_text
    assert "{{{REDACTED-iban-code}}}" in r.filtered_text


class TestAllowSpaces:
    """Matches the Java option: same name, same ``true`` default."""

    def test_default_is_on(self):
        assert IBANCodeFilter().allow_spaces is True
        assert IBANCodeFilter({}).allow_spaces is True
        assert IBANCodeFilter(None).allow_spaces is True

    def test_explicit_true(self):
        f = IBANCodeFilter({"allowSpaces": True})
        assert [s.text for s in f.detect("GB82 WEST 1234 5698 7654 32")] == [
            "GB82 WEST 1234 5698 7654 32"
        ]

    def test_false_rejects_the_printed_form(self):
        f = IBANCodeFilter({"allowSpaces": False})
        assert f.detect("GB82 WEST 1234 5698 7654 32") == []

    def test_false_keeps_the_transmitted_form(self):
        f = IBANCodeFilter({"allowSpaces": False})
        assert [s.text for s in f.detect("GB29NWBK60161331926819")] == [
            "GB29NWBK60161331926819"
        ]

    @pytest.mark.parametrize("iban", REAL_IBANS)
    def test_transmitted_form_unaffected_by_the_option(self, iban):
        assert [s.text for s in IBANCodeFilter().detect(iban)] == [iban]
        assert [s.text for s in IBANCodeFilter({"allowSpaces": False}).detect(iban)] == [iban]


class TestSpacedBoundaries:
    def test_single_space_only(self, filt):
        assert filt.detect("GB82  WEST  1234  5698  7654  32") == []

    def test_hyphens_are_not_group_separators(self, filt):
        assert filt.detect("GB82-WEST-1234-5698-7654-32") == []

    def test_lowercase_word_after_is_not_absorbed(self, filt):
        assert [s.text for s in filt.detect("ES91 2100 0418 4502 0005 1332 paid")] == [
            "ES91 2100 0418 4502 0005 1332"
        ]

    def test_punctuation_ends_the_match(self, filt):
        assert [s.text for s in filt.detect("ES91 2100 0418 4502 0005 1332.")] == [
            "ES91 2100 0418 4502 0005 1332"
        ]

    def test_iban_after_a_same_shaped_word_is_still_found(self, filt):
        # Regression: a leading "ZZ99" used to swallow the IBAN behind it.
        assert [s.text for s in filt.detect("ZZ99 GB29NWBK60161331926819")] == [
            "GB29NWBK60161331926819"
        ]
        assert [s.text for s in filt.detect("AB12 CD34 GB29NWBK60161331926819")] == [
            "GB29NWBK60161331926819"
        ]

    def test_trailing_upper_case_word_is_absorbed(self, filt):
        # A short upper-case word after a full final group reads as another group.
        assert [s.text for s in filt.detect("ES91 2100 0418 4502 0005 1332 PAID")] == [
            "ES91 2100 0418 4502 0005 1332 PAID"
        ]
        assert [s.text for s in filt.detect("GB29NWBK60161331926819 ZZ99")] == [
            "GB29NWBK60161331926819 ZZ99"
        ]
