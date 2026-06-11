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

from phileas.filters.bank_routing_number_filter import BankRoutingNumberFilter


FILTER_TYPE = "bank-routing-number"


@pytest.fixture
def filt():
    return BankRoutingNumberFilter()


# ---------------------------------------------------------------------------
# Positive cases
# ---------------------------------------------------------------------------

# Real / valid-prefix 9-digit ABA routing numbers.
POSITIVE_NUMBERS = [
    "011000015",  # prefix 01
    "021000021",  # prefix 02
    "123456789",  # prefix 12
    "322271627",  # prefix 32
    "010000000",  # boundary 01
    "120000000",  # boundary 12
    "210000000",  # boundary 21
    "320000000",  # boundary 32
    "090000000",  # prefix 09
    "110000000",  # prefix 11
    "250000000",  # prefix 25
    "310000000",  # prefix 31
]


@pytest.mark.parametrize("number", POSITIVE_NUMBERS)
def test_detects_routing_numbers(filt, number):
    spans = filt.detect(number)
    assert len(spans) == 1
    assert spans[0].text == number


@pytest.mark.parametrize("number", POSITIVE_NUMBERS)
def test_span_attributes(filt, number):
    span = filt.detect(number)[0]
    assert span.filter_type == FILTER_TYPE
    assert span.character_start == 0
    assert span.character_end == 9
    assert span.character_end == len(number)
    assert span.confidence == 1.0
    # detect() never sets a replacement
    assert span.replacement == ""


@pytest.mark.parametrize("prefix", ["01", "02", "12", "21", "29", "32"])
def test_all_valid_prefixes(filt, prefix):
    number = prefix + "0000000"
    spans = filt.detect(number)
    assert len(spans) == 1
    assert spans[0].text == number


def test_number_in_sentence(filt):
    text = "My ABA is 011000015 thanks."
    spans = filt.detect(text)
    assert len(spans) == 1
    assert spans[0].text == "011000015"
    assert spans[0].character_start == 10
    assert spans[0].character_end == 19
    assert text[spans[0].character_start : spans[0].character_end] == spans[0].text


def test_number_with_trailing_period(filt):
    text = "Routing: 021000021."
    spans = filt.detect(text)
    assert len(spans) == 1
    assert spans[0].text == "021000021"
    assert spans[0].character_start == 9
    assert spans[0].character_end == 18


def test_multiple_numbers(filt):
    text = "021000021 and 011000015"
    spans = filt.detect(text)
    assert len(spans) == 2
    assert [s.text for s in spans] == ["021000021", "011000015"]
    assert spans[0].character_start == 0
    assert spans[1].character_start == 14


def test_number_after_short_number(filt):
    # A leading 2-digit token does not consume the real 9-digit match.
    text = "03 011000015"
    spans = filt.detect(text)
    assert len(spans) == 1
    assert spans[0].text == "011000015"
    assert spans[0].character_start == 3


def test_returns_list_empty(filt):
    result = filt.detect("no routing numbers here")
    assert isinstance(result, list)
    assert result == []


def test_context_passed_through(filt):
    spans = filt.detect("011000015", context="ctx-name")
    assert len(spans) == 1
    assert spans[0].context == "ctx-name"


def test_default_config_none():
    # Constructing with explicit None behaves the same as default {}.
    f = BankRoutingNumberFilter(None)
    assert len(f.detect("011000015")) == 1


def test_default_config_empty_dict():
    f = BankRoutingNumberFilter({})
    assert len(f.detect("011000015")) == 1


# ---------------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------------

NEGATIVE_CASES = [
    "",
    "no routing numbers here",
    # First two digits out of range.
    "000000000",  # prefix 00
    "130000000",  # prefix 13
    "200000000",  # prefix 20
    "330000000",  # prefix 33
    "990000000",  # prefix 99
    "140000000",  # prefix 14 (between 12 and 21)
    "190000000",  # prefix 19
    # Wrong length.
    "12345678",   # 8 digits
    "1234567890",  # 10 digits
    "01100001",   # 8 digits, valid prefix
    "0110000155",  # 10 digits, valid prefix
    "29999999",   # 8 digits
]


@pytest.mark.parametrize("text", NEGATIVE_CASES)
def test_negative_no_detection(filt, text):
    assert filt.detect(text) == []


@pytest.mark.parametrize("prefix", ["00", "13", "20", "33", "40", "99"])
def test_out_of_range_prefixes(filt, prefix):
    number = prefix + "0000000"
    assert filt.detect(number) == []


def test_embedded_in_longer_digit_run_not_matched(filt):
    # No word boundary around a valid 9-digit core => not detected.
    assert filt.detect("x011000015x") == []
    assert filt.detect("0011000015") == []
    assert filt.detect("0110000150") == []


def test_too_short_run_inside_text(filt):
    assert filt.detect("ref 12345678 done") == []


def test_too_long_run_inside_text(filt):
    assert filt.detect("ref 1234567890 done") == []
