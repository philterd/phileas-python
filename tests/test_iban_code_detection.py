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
