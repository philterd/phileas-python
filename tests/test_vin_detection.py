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

"""Detection tests for the VINFilter filter."""

import pytest

from phileas.filters.vin_filter import VINFilter


# Valid 17-character VINs (uppercase, no I/O/Q).
VALID_VINS = [
    "1HGCM82633A004352",
    "JH4KA7561PC008269",
    "5YJSA1E26HF000337",
    "19UYA31581L000000",
    "AAAAAAAAAAAAAAAAA",
    "1234567890ABCDEFG",
    "WBANE53578CT12345",
]


@pytest.fixture
def vin_filter():
    return VINFilter()


@pytest.mark.parametrize("vin", VALID_VINS)
def test_valid_vin_detected_standalone(vin_filter, vin):
    spans = vin_filter.detect(vin)
    assert len(spans) == 1
    span = spans[0]
    assert span.text == vin
    assert span.character_start == 0
    assert span.character_end == 17
    assert span.filter_type == "vin"
    assert span.confidence == 1.0
    assert span.replacement == ""


@pytest.mark.parametrize("vin", VALID_VINS)
def test_valid_vin_detected_in_sentence(vin_filter, vin):
    text = f"The vehicle VIN is {vin} on record."
    spans = vin_filter.detect(text)
    assert len(spans) == 1
    span = spans[0]
    assert span.text == vin
    assert text[span.character_start : span.character_end] == vin
    assert span.filter_type == "vin"


def test_multiple_vins_in_text(vin_filter):
    text = "VIN1: 1HGCM82633A004352 VIN2: JH4KA7561PC008269"
    spans = vin_filter.detect(text)
    assert len(spans) == 2
    assert {s.text for s in spans} == {"1HGCM82633A004352", "JH4KA7561PC008269"}
    for s in spans:
        assert s.filter_type == "vin"
        assert text[s.character_start : s.character_end] == s.text


@pytest.mark.parametrize(
    "wrapped",
    [
        "1HGCM82633A004352.",
        "(1HGCM82633A004352)",
        "1HGCM82633A004352,",
        "[1HGCM82633A004352]",
    ],
)
def test_vin_with_surrounding_punctuation(vin_filter, wrapped):
    spans = vin_filter.detect(wrapped)
    assert len(spans) == 1
    assert spans[0].text == "1HGCM82633A004352"


def test_default_context_returns_results(vin_filter):
    spans = vin_filter.detect("1HGCM82633A004352", context="default")
    assert len(spans) == 1


def test_custom_context_still_detects(vin_filter):
    spans = vin_filter.detect("1HGCM82633A004352", context="custom-ctx")
    assert len(spans) == 1


# --- Negative cases ---------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "1HGCM82633A00435",  # 16 chars
        "1HGCM82633A0043",  # 15 chars
        "ABCDEFGHJKLMNPRST",  # this one is actually 17 valid -> handled separately
    ][:2],
)
def test_too_short_not_detected(vin_filter, text):
    assert vin_filter.detect(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "1HGCM82633A0043520",  # 18 chars
        "AAAAAAAAAAAAAAAAAA",  # 18 A's
        "A1HGCM82633A004352",  # 18 chars (leading)
        "1HGCM82633A004352B",  # 18 chars (trailing)
    ],
)
def test_too_long_not_detected(vin_filter, text):
    assert vin_filter.detect(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "1HGIM82633A004352",  # contains I
        "1HGOM82633A004352",  # contains O
        "1HGQM82633A004352",  # contains Q
        "IIIIIIIIIIIIIIIII",  # all I
        "OOOOOOOOOOOOOOOOO",  # all O
        "QQQQQQQQQQQQQQQQQ",  # all Q
        "1HGCM82633A00435I",  # I at end
        "O1GCM82633A004352",  # O at start
    ],
)
def test_illegal_letters_not_detected(vin_filter, text):
    assert vin_filter.detect(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "1hgcm82633a004352",  # all lowercase
        "1HGcm82633A004352",  # mixed case
    ],
)
def test_lowercase_not_detected(vin_filter, text):
    assert vin_filter.detect(text) == []


def test_vin_glued_to_word_not_detected(vin_filter):
    # No word boundary: surrounding alphanumerics extend the token past 17.
    assert vin_filter.detect("AAAAAAAAAAAAAAAAAA1HGCM82633A004352BBBBB") == []


@pytest.mark.parametrize(
    "text",
    [
        "",
        "no vin here at all",
        "just some words 12345 and ABCDE",
        "phone 555-123-4567 not a vin",
    ],
)
def test_no_false_positives(vin_filter, text):
    assert vin_filter.detect(text) == []


def test_seventeen_letters_excluding_ioq_is_valid(vin_filter):
    # 17 valid characters drawn from the allowed alphabet (no I/O/Q).
    vin = "ABCDEFGHJKLMNPRST"
    assert len(vin) == 17
    spans = vin_filter.detect(vin)
    assert len(spans) == 1
    assert spans[0].text == vin


def test_filter_constructs_with_none_config():
    f = VINFilter(None)
    spans = f.detect("1HGCM82633A004352")
    assert len(spans) == 1
    assert spans[0].filter_type == "vin"


def test_filter_constructs_with_empty_config():
    f = VINFilter({})
    spans = f.detect("1HGCM82633A004352")
    assert len(spans) == 1
