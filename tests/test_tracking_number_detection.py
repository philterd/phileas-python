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

from phileas.filters.tracking_number_filter import TrackingNumberFilter


FILTER_TYPE = "tracking-number"


@pytest.fixture
def filt():
    return TrackingNumberFilter()


# ---------------------------------------------------------------------------
# Positive cases
# ---------------------------------------------------------------------------

POSITIVE_CASES = [
    # UPS: 1Z followed by 16 alphanumeric characters (18 total).
    "1Z9999W99999999999",
    "1Z999AA10123456784",
    "1ZA1B2C3D4E5F6G7H8",
    # FedEx: 12-digit number.
    "123456789012",
    "987654321098",
    # FedEx: 15-digit number.
    "123456789012345",
    "999888777666555",
    # USPS: 22-digit numbers starting with 92/93/94/95.
    "9261290100000000000000",
    "9300100000000000000000",
    "9400100000000000000000",
    "9500100000000000000000",
    # International "XX#########US": two letters, 9 digits, then US.
    "RA123456789US",
    "CP123456789US",
    "LZ000000001US",
]


@pytest.mark.parametrize("value", POSITIVE_CASES)
def test_detects_positive(filt, value):
    spans = filt.detect(value)
    assert len(spans) == 1
    assert spans[0].text == value


@pytest.mark.parametrize("value", POSITIVE_CASES)
def test_span_attributes(filt, value):
    span = filt.detect(value)[0]
    assert span.filter_type == FILTER_TYPE
    assert span.character_start == 0
    assert span.character_end == len(value)
    assert span.confidence == 1.0
    # detect() never sets a replacement.
    assert span.replacement == ""


def test_ups_lowercase_matches(filt):
    # The UPS pattern is case-insensitive, so a lowercase prefix still matches.
    value = "1z999aa10123456784"
    spans = filt.detect(value)
    assert len(spans) == 1
    assert spans[0].text == value


def test_detects_in_sentence(filt):
    text = "Your package 1Z999AA10123456784 is out for delivery."
    spans = filt.detect(text)
    assert len(spans) == 1
    assert spans[0].text == "1Z999AA10123456784"
    assert spans[0].character_start == 13
    assert text[spans[0].character_start : spans[0].character_end] == spans[0].text


def test_usps_in_sentence_offsets(filt):
    num = "9400100000000000000000"
    text = "Tracking: " + num + " arrived"
    spans = filt.detect(text)
    assert len(spans) == 1
    assert spans[0].text == num
    assert spans[0].character_start == 10
    assert spans[0].character_end == 10 + len(num)


def test_international_in_sentence(filt):
    num = "RA123456789US"
    text = "Track " + num + " now"
    spans = filt.detect(text)
    assert len(spans) == 1
    assert spans[0].text == num
    assert spans[0].character_start == 6


def test_multiple_tracking_numbers(filt):
    ups = "1Z999AA10123456784"
    fedex = "123456789012345"
    text = ups + " and " + fedex
    spans = filt.detect(text)
    found = {s.text for s in spans}
    assert found == {ups, fedex}
    assert len(spans) == 2


def test_two_fedex_numbers(filt):
    text = "123456789012 and 123456789012345"
    spans = filt.detect(text)
    found = {s.text for s in spans}
    assert found == {"123456789012", "123456789012345"}
    assert len(spans) == 2


def test_usps_22_digit_matched_once(filt):
    # A 22-digit USPS number is bounded by word boundaries so the FedEx
    # 12/15-digit pattern does not also match a substring inside it.
    num = "9400100000000000000000"
    spans = filt.detect(num)
    assert len(spans) == 1
    assert spans[0].text == num


def test_returns_list(filt):
    result = filt.detect("no tracking numbers here")
    assert isinstance(result, list)
    assert result == []


def test_context_passed_through(filt):
    spans = filt.detect("123456789012", context="ctx-name")
    assert len(spans) == 1
    assert spans[0].context == "ctx-name"


def test_default_config_none():
    # Constructing with explicit None behaves the same as default {}.
    f = TrackingNumberFilter(None)
    assert len(f.detect("123456789012")) == 1


def test_default_config_empty_dict():
    f = TrackingNumberFilter({})
    assert len(f.detect("123456789012")) == 1


# ---------------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------------

NEGATIVE_CASES = [
    "",
    "no tracking here",
    "package number 42",
    # Wrong digit lengths for FedEx (not 12 or 15).
    "123456789",          # 9 digits
    "12345678901",        # 11 digits
    "1234567890123",      # 13 digits
    "12345678901234",     # 14 digits
    "1234567890123456",   # 16 digits
    # USPS must be exactly 22 digits; a 20-digit number does not match.
    "92612901000000000000",   # 20 digits
    "926129010000000000000",  # 21 digits
    # USPS 22 digits but wrong leading pair (96 not in 92-95).
    "9600100000000000000000",
    "9100100000000000000000",
    # UPS wrong trailing length.
    "1Z999999999999999",    # 1Z + 15
    "1Z99999999999999999",  # 1Z + 17
    # International format: lowercase is not accepted by that pattern.
    "ra123456789us",
    # International format wrong digit count.
    "RA12345678US",     # 8 digits
    "RA1234567890US",   # 10 digits
    # International format wrong suffix.
    "RA123456789CA",
    # International format wrong prefix (digits, not letters).
    "12123456789US",
]


@pytest.mark.parametrize("text", NEGATIVE_CASES)
def test_negative_no_detection(filt, text):
    assert filt.detect(text) == []


def test_embedded_in_longer_digit_run_not_matched(filt):
    # A 12-digit run glued to more digits has no word boundary and is not
    # detected as a standalone FedEx number.
    assert filt.detect("12345678901234567890") == []
