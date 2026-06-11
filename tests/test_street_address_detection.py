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

"""Detection tests for the StreetAddressFilter filter."""

import pytest

from phileas.filters.street_address_filter import StreetAddressFilter


@pytest.fixture
def street_filter():
    return StreetAddressFilter()


# Addresses that should be detected in full when standing alone.
POSITIVE_ADDRESSES = [
    "123 Main Street",
    "456 Oak Avenue",
    "1 Martin Luther King Jr Blvd",
    "100 Main St",
    "200 Oak Ave",
    "300 Park Boulevard",
    "350 Park Blvd",
    "400 Elm Road",
    "410 Elm Rd",
    "500 Pine Lane",
    "510 Pine Ln",
    "600 First Drive",
    "610 First Dr",
    "700 Second Court",
    "710 Second Ct",
    "800 Third Place",
    "810 Third Pl",
    "900 Fourth Way",
    "1000 Fifth Circle",
    "1010 Fifth Cir",
    "1100 Sixth Terrace",
    "1110 Sixth Ter",
    "1200 Seventh Trail",
    "1210 Seventh Trl",
]


@pytest.mark.parametrize("addr", POSITIVE_ADDRESSES)
def test_address_detected_standalone(street_filter, addr):
    spans = street_filter.detect(addr)
    assert len(spans) == 1
    span = spans[0]
    assert span.text == addr
    assert span.character_start == 0
    assert span.character_end == len(addr)
    assert span.filter_type == "street-address"
    assert span.confidence == 1.0
    assert span.replacement == ""


@pytest.mark.parametrize("addr", POSITIVE_ADDRESSES)
def test_address_detected_in_sentence(street_filter, addr):
    text = f"I live at {addr} now."
    spans = street_filter.detect(text)
    assert len(spans) == 1
    span = spans[0]
    assert span.text == addr
    assert text[span.character_start : span.character_end] == addr
    assert span.filter_type == "street-address"


@pytest.mark.parametrize(
    "text,expected",
    [
        ("123 main street", "123 main street"),
        ("123 MAIN STREET", "123 MAIN STREET"),
        ("123 Main STREET", "123 Main STREET"),
        ("456 oak ave", "456 oak ave"),
    ],
)
def test_case_insensitive(street_filter, text, expected):
    spans = street_filter.detect(text)
    assert len(spans) == 1
    assert spans[0].text == expected


def test_multiple_addresses_in_text(street_filter):
    text = "I live at 123 Main Street and you at 456 Oak Avenue"
    spans = street_filter.detect(text)
    assert len(spans) == 2
    assert {s.text for s in spans} == {"123 Main Street", "456 Oak Avenue"}
    for s in spans:
        assert s.filter_type == "street-address"
        assert text[s.character_start : s.character_end] == s.text


def test_multi_word_street_name(street_filter):
    text = "Visit 1 Martin Luther King Jr Blvd, Suite 200"
    spans = street_filter.detect(text)
    assert len(spans) == 1
    assert spans[0].text == "1 Martin Luther King Jr Blvd"


def test_long_street_name_within_word_limit(street_filter):
    addr = "12345 Long Street Name Boulevard"
    spans = street_filter.detect(addr)
    assert len(spans) == 1
    assert spans[0].text == addr


def test_default_context_returns_results(street_filter):
    spans = street_filter.detect("123 Main Street", context="default")
    assert len(spans) == 1
    assert spans[0].context == "default"


def test_custom_context_still_detects(street_filter):
    spans = street_filter.detect("123 Main Street", context="custom-ctx")
    assert len(spans) == 1
    assert spans[0].context == "custom-ctx"


# --- Negative cases ---------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "",
        "just plain text here",
        "No address",
        "street",
        "Main Street",  # no leading number
        "123 Street",  # no street-name word between number and suffix
        "PO Box 123",
        "P.O. Box 456",
        "phone 555-123-4567 not an address",
        "123 Main Streets",  # trailing 's' breaks the suffix word boundary
        "123 Main Streetss",
        "123456 Main Street",  # number has six digits (exceeds \\d{1,5})
    ],
)
def test_no_detection(street_filter, text):
    assert street_filter.detect(text) == []


def test_filter_constructs_with_none_config():
    f = StreetAddressFilter(None)
    spans = f.detect("123 Main Street")
    assert len(spans) == 1
    assert spans[0].filter_type == "street-address"


def test_filter_constructs_with_empty_config():
    f = StreetAddressFilter({})
    spans = f.detect("123 Main Street")
    assert len(spans) == 1
    assert spans[0].filter_type == "street-address"
