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
    assert span.confidence == 0.85
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
    assert spans[0].text == "1 Martin Luther King Jr Blvd, Suite 200"


def test_long_street_name_within_word_limit(street_filter):
    addr = "12345 Long Street Name Boulevard"
    spans = street_filter.detect(addr)
    assert len(spans) == 1
    assert spans[0].text == addr


def test_no_match_across_line_breaks(street_filter):
    # A ZIP code at the end of a line and "Dear Dr." on the next line are not an address.
    text = "Address: 214 Juniper Court, Cedar Falls, IA 50613\n\nDear Dr. Rivera,"
    spans = street_filter.detect(text)
    assert [s.text for s in spans] == ["214 Juniper Court"]


@pytest.mark.parametrize(
    "text,expected",
    [
        ("214 Juniper Court\nCedar Falls, IA 50613", "214 Juniper Court"),
        ("123 Main St Apt 4B\r\nSpringfield, IL 62704", "123 Main St Apt 4B"),
        ("Jane Doe\n1 Martin Luther King Jr Blvd\nAtlanta, GA 30303", "1 Martin Luther King Jr Blvd"),
    ],
)
def test_street_line_of_address_block(street_filter, text, expected):
    spans = street_filter.detect(text)
    assert [s.text for s in spans] == [expected]


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
        "phone 555-123-4567 not an address",
        "123 Main Streets",  # trailing 's' breaks the suffix word boundary
        "123 Main Streetss",
        "1234567 Main Street",  # number has seven digits (exceeds \\d{1,6})
        "Cedar Falls, IA 50613\nDear Dr. Rivera,",  # parts on different lines
        "Cedar Falls, IA 50613\r\nDear Dr. Rivera,",
        "Unit 12\nMain Street",
        "Chapter 4 summary",
        "Meeting at 3 PM today",
        "Section 5 covers everything",
        "PO Box without a number",
        "P.O. Box\n12",
        "Post Office\nBox 789",
    ],
)
def test_no_detection(street_filter, text):
    assert street_filter.detect(text) == []


# --- Ported from the Phileas (Java) StreetAddressFilterTest -----------------


@pytest.mark.parametrize(
    "text,start,end",
    [
        ("lived at 100 Main St", 9, 20),
        ("lived at 100 S Main St", 9, 22),
        ("lived at 100 South Main St", 9, 26),
        ("lived at 1000 Main Street", 9, 25),
        ("North 2800 Clay Edwards Drive", 6, 29),
        ("14 Southampton St.", 0, 18),
        ("22 Newport Drive", 0, 16),
        ("78 Glendale Street", 0, 18),
        ("6 Berkshire Court", 0, 17),
        ("291 North Pawnee Ave.", 0, 21),
        ("468 William Street", 0, 18),
        ("291 6th Dr.", 0, 11),
        ("9444 Heritage St.", 0, 17),
        ("70 Birchpond Street", 0, 19),
        ("656 S. Inverness St.", 0, 20),
        ("9142 Arlington Court", 0, 20),
        ("4 Devonshire Ct.", 0, 16),
        ("4 Devonshire Ct", 0, 15),
        ("4 Devonshire Ct ste 2", 0, 21),
        ("4 Devonshire Ct apartment 222", 0, 29),
        ("4 Devonshire Ct apt 222", 0, 23),
        ("4 Devonshire Ct apt 222 anywhere", 0, 23),
        ("address is 9444 Heritage St. over there", 11, 28),
        ("address is 9444 Heritage St. apt 2 over there", 11, 34),
        ("445 Minnesota Street, Suite 175", 0, 31),
    ],
)
def test_java_span_offsets(street_filter, text, start, end):
    spans = street_filter.detect(text)
    assert len(spans) == 1
    assert (spans[0].character_start, spans[0].character_end) == (start, end)
    assert spans[0].confidence == 0.85


@pytest.mark.parametrize(
    "text",
    [
        # Directionals
        "123 N Main St",
        "123 North Main Street",
        "123 Main St NW",
        # Ordinals
        "123 5th Avenue",
        "42 42nd Street",
        # Street types added from Java
        "10 Sunset Loop",
        "5 Kings Crossing",
        "12 Harbor Plaza",
        "34 Oak Point",
        "77 Rectory Mews",
        "900 Coastal Highway",
        "1 Elm Parkway",
        # House number ranges and letters
        "123-125 Main St",
        "100-102 Main St",
        "123A Main Street",
        # Saint and apostrophe names
        "100 St. Charles Avenue",
        "12 O'Connor Way",
        # Units
        "123 Main St Apt 4B",
        "12 Pine Rd #5",
        "100 Main St NW",
        # PO boxes
        "PO Box 1234",
        "P.O. Box 56",
        "Post Office Box 789",
    ],
)
def test_java_address_forms_detected_in_full(street_filter, text):
    assert [s.text for s in street_filter.detect(text)] == [text]


@pytest.mark.parametrize(
    "text,expected",
    [
        ("123-125 Oak Ave, Apt 4B\r\nCedar Falls, IA 50613", "123-125 Oak Ave, Apt 4B"),
        ("123 N Main St NW\nSpringfield, IL 62704", "123 N Main St NW"),
        ("12 Pine Rd\nRoom 5 is booked", "12 Pine Rd"),
    ],
)
def test_java_address_blocks(street_filter, text, expected):
    assert [s.text for s in street_filter.detect(text)] == [expected]


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
