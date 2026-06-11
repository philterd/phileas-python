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

"""Characterization tests for ZipCodeFilter detection."""

from __future__ import annotations

import pytest

from phileas.filters.zip_code_filter import ZipCodeFilter


FILTER_TYPE = "zip-code"


@pytest.fixture
def zip_filter():
    return ZipCodeFilter()


def texts(spans):
    return [s.text for s in spans]


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

def test_construct_default_filter_type():
    assert ZipCodeFilter().filter_type == FILTER_TYPE


def test_construct_with_none_config():
    f = ZipCodeFilter(None)
    assert f.filter_type == FILTER_TYPE
    assert f.config == {}


def test_construct_with_empty_dict_config():
    f = ZipCodeFilter({})
    assert f.filter_type == FILTER_TYPE
    assert f.config == {}


# ---------------------------------------------------------------------------
# Positive: 5-digit zip codes
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "zip_text",
    ["12345", "90210", "30033", "00000", "99999", "10001"],
)
def test_five_digit_zip_detected(zip_filter, zip_text):
    spans = zip_filter.detect(zip_text)
    assert len(spans) == 1
    span = spans[0]
    assert span.text == zip_text
    assert span.filter_type == FILTER_TYPE
    assert span.character_start == 0
    assert span.character_end == 5
    assert span.confidence == 1.0
    assert span.replacement == ""


def test_five_digit_zip_in_sentence(zip_filter):
    spans = zip_filter.detect("My zip is 30033.")
    assert len(spans) == 1
    span = spans[0]
    assert span.text == "30033"
    assert span.character_start == 10
    assert span.character_end == 15


def test_five_digit_zip_surrounded_by_words(zip_filter):
    spans = zip_filter.detect("abc 90210 def")
    assert len(spans) == 1
    assert spans[0].text == "90210"
    assert spans[0].character_start == 4
    assert spans[0].character_end == 9


def test_multiple_five_digit_zips(zip_filter):
    spans = zip_filter.detect("12345 67890")
    assert texts(spans) == ["12345", "67890"]
    assert spans[0].character_start == 0
    assert spans[1].character_start == 6


# ---------------------------------------------------------------------------
# Positive: ZIP+4 codes
#
# Both patterns run, so a ZIP+4 produces TWO spans: the full "12345-6789"
# match plus the embedded 5-digit "12345" match.
# ---------------------------------------------------------------------------

def test_zip_plus_four_detected(zip_filter):
    spans = zip_filter.detect("12345-6789")
    assert texts(spans) == ["12345-6789", "12345"]


def test_zip_plus_four_full_span(zip_filter):
    spans = zip_filter.detect("12345-6789")
    full = spans[0]
    assert full.text == "12345-6789"
    assert full.character_start == 0
    assert full.character_end == 10
    assert full.filter_type == FILTER_TYPE
    assert full.confidence == 1.0
    assert full.replacement == ""


def test_zip_plus_four_embedded_five_digit_span(zip_filter):
    spans = zip_filter.detect("12345-6789")
    embedded = spans[1]
    assert embedded.text == "12345"
    assert embedded.character_start == 0
    assert embedded.character_end == 5


def test_zip_plus_four_in_sentence(zip_filter):
    spans = zip_filter.detect("zip 90210-1234 end")
    assert texts(spans) == ["90210-1234", "90210"]
    assert spans[0].character_start == 4
    assert spans[0].character_end == 14
    assert spans[1].character_start == 4
    assert spans[1].character_end == 9


# ---------------------------------------------------------------------------
# Negative: too few / too many digits
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "text",
    [
        "",
        "1234",          # 4 digits
        "123",           # 3 digits
        "1",
        "123456",        # 6 digits (no word boundary inside)
        "1234567",       # 7 digits
        "123456789",     # 9 digits
        "1234567890",    # 10 digits
        "no zips here",
        "abcde",
        "zip code",
    ],
)
def test_no_zip_detected(zip_filter, text):
    assert zip_filter.detect(text) == []


# ---------------------------------------------------------------------------
# Negative: digits adjacent to word characters (no \b boundary)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "text",
    ["A12345", "12345A", "x12345y", "abc12345"],
)
def test_letter_adjacent_digits_not_detected(zip_filter, text):
    assert zip_filter.detect(text) == []


# ---------------------------------------------------------------------------
# Partial / malformed ZIP+4 falls back to the 5-digit match only
# ---------------------------------------------------------------------------

def test_zip_plus_three_only_five_digit(zip_filter):
    # "12345-678" has only 3 trailing digits -> not a ZIP+4, but the leading
    # "12345" is still a valid 5-digit match.
    spans = zip_filter.detect("12345-678")
    assert texts(spans) == ["12345"]
    assert spans[0].character_start == 0
    assert spans[0].character_end == 5


def test_zip_plus_five_splits_into_two_five_digit(zip_filter):
    # "12345-67890" is not ZIP+4 (5 trailing digits); both 5-digit groups match.
    spans = zip_filter.detect("12345-67890")
    assert texts(spans) == ["12345", "67890"]
    assert spans[0].character_start == 0
    assert spans[0].character_end == 5
    assert spans[1].character_start == 6
    assert spans[1].character_end == 11


def test_dot_separated_only_five_digit(zip_filter):
    spans = zip_filter.detect("12345.6789")
    assert texts(spans) == ["12345"]
    assert spans[0].character_start == 0
    assert spans[0].character_end == 5


# ---------------------------------------------------------------------------
# Context propagation
# ---------------------------------------------------------------------------

def test_default_context(zip_filter):
    span = zip_filter.detect("90210")[0]
    assert span.context == "default"


def test_custom_context(zip_filter):
    span = zip_filter.detect("90210", context="ctx")[0]
    assert span.context == "ctx"
