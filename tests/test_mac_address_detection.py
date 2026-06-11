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

from phileas.filters.mac_address_filter import MACAddressFilter


FILTER_TYPE = "mac-address"


@pytest.fixture
def filt():
    return MACAddressFilter()


# ---------------------------------------------------------------------------
# Positive cases
# ---------------------------------------------------------------------------

VALID_MACS = [
    # Colon-separated, lower hex
    "00:1a:2b:3c:4d:5e",
    # Colon-separated, upper hex
    "00:1A:2B:3C:4D:5E",
    # Colon-separated, all uppercase
    "AA:BB:CC:DD:EE:FF",
    # Colon-separated, all lowercase
    "aa:bb:cc:dd:ee:ff",
    # Colon-separated, mixed case
    "Ab:cD:00:Ff:9a:B2",
    # Dash-separated, lower hex
    "00-1a-2b-3c-4d-5e",
    # Dash-separated, upper hex
    "00-1A-2B-3C-4D-5E",
    # Dash-separated, all uppercase
    "AA-BB-CC-DD-EE-FF",
    # All digits
    "01:23:45:67:89:01",
    # All hex letters
    "ab:cd:ef:ab:cd:ef",
]


@pytest.mark.parametrize("mac", VALID_MACS)
def test_detects_valid_macs(filt, mac):
    spans = filt.detect(mac)
    assert len(spans) == 1
    assert spans[0].text == mac


@pytest.mark.parametrize("mac", VALID_MACS)
def test_span_attributes(filt, mac):
    span = filt.detect(mac)[0]
    assert span.filter_type == FILTER_TYPE
    assert span.character_start == 0
    assert span.character_end == len(mac)
    assert span.confidence == 1.0
    # detect() never sets a replacement
    assert span.replacement == ""


def test_mac_with_mixed_separators(filt):
    # The pattern allows mixing ':' and '-' between groups.
    mac = "00:1A-2B:3C-4D:5E"
    spans = filt.detect(mac)
    assert len(spans) == 1
    assert spans[0].text == mac


def test_mac_in_sentence(filt):
    text = "The device mac is 00:1A:2B:3C:4D:5E in the table."
    spans = filt.detect(text)
    assert len(spans) == 1
    assert spans[0].text == "00:1A:2B:3C:4D:5E"
    assert spans[0].character_start == 18
    assert text[spans[0].character_start : spans[0].character_end] == spans[0].text


def test_mac_offsets_in_sentence(filt):
    mac = "aa-bb-cc-dd-ee-ff"
    text = "abc " + mac + " xyz"
    spans = filt.detect(text)
    assert len(spans) == 1
    assert spans[0].character_start == 4
    assert spans[0].character_end == 4 + len(mac)
    assert spans[0].text == mac


def test_multiple_macs(filt):
    a = "00:1A:2B:3C:4D:5E"
    b = "aa-bb-cc-dd-ee-ff"
    text = f"{a} and {b}"
    spans = filt.detect(text)
    found = {s.text for s in spans}
    assert found == {a, b}
    assert len(spans) == 2


def test_seven_groups_matches_first_six(filt):
    # A 7-group string has a word boundary after the 6th group, so only the
    # first six groups are detected.
    text = "00:1A:2B:3C:4D:5E:6F"
    spans = filt.detect(text)
    assert len(spans) == 1
    assert spans[0].text == "00:1A:2B:3C:4D:5E"
    assert spans[0].character_start == 0
    assert spans[0].character_end == 17


def test_leading_colon_does_not_break_match(filt):
    text = ":00:1A:2B:3C:4D:5E"
    spans = filt.detect(text)
    assert len(spans) == 1
    assert spans[0].text == "00:1A:2B:3C:4D:5E"


def test_returns_list_empty(filt):
    result = filt.detect("nothing to see here")
    assert isinstance(result, list)
    assert result == []


def test_context_passed_through(filt):
    spans = filt.detect("00:1A:2B:3C:4D:5E", context="ctx-name")
    assert len(spans) == 1
    assert spans[0].context == "ctx-name"


def test_default_config_none():
    # Constructing with explicit None behaves the same as the default {}.
    f = MACAddressFilter(None)
    assert len(f.detect("00:1A:2B:3C:4D:5E")) == 1


def test_default_config_empty_dict():
    f = MACAddressFilter({})
    assert len(f.detect("00:1A:2B:3C:4D:5E")) == 1


# ---------------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------------

NEGATIVE_CASES = [
    # Empty
    "",
    # Plain text
    "no mac here",
    # Too few groups (5 groups)
    "00:1A:2B:3C:4D",
    # Too few groups (4 groups)
    "00:1A:2B:3C",
    # Trailing separator, missing final group
    "00:1A:2B:3C:4D:",
    # Non-hex characters in a group
    "00:1G:2B:3C:4D:5E",
    # All non-hex letters
    "GG:HH:II:JJ:KK:LL",
    # No separators at all (12 contiguous hex chars)
    "001A2B3C4D5E",
    # Single-digit groups (not two hex digits each)
    "0:1:2:3:4:5",
    "1:2:3:4:5:6",
    # Three-digit leading group with no preceding boundary char run
    "000:1A:2B:3C:4D:5E",
    # Glued to hex letters on the left -> no word boundary
    "xa00:1A:2B:3C:4D:5E",
    # Trailing extra hex digits glued on -> no word boundary at end
    "00:1A:2B:3C:4D:5EFF",
    # Period-separated (Cisco style) is not supported by this pattern
    "001a.2b3c.4d5e",
    # Space-separated groups
    "00 1A 2B 3C 4D 5E",
]


@pytest.mark.parametrize("text", NEGATIVE_CASES)
def test_negative_no_detection(filt, text):
    assert filt.detect(text) == []


def test_group_with_three_hex_digits_not_matched(filt):
    # Each group must be exactly two hex digits; a three-digit group breaks it.
    assert filt.detect("000:1A:2B:3C:4D:5E") == []


def test_embedded_in_word_not_matched(filt):
    mac = "00:1A:2B:3C:4D:5E"
    text = "xx" + mac + "xx"
    assert filt.detect(text) == []
