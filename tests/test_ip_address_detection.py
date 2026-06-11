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

from phileas.filters.ip_address_filter import IPAddressFilter


@pytest.fixture
def filt():
    return IPAddressFilter()


# ---------------------------------------------------------------------------
# Positive IPv4 cases
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "text",
    [
        "192.168.1.1",
        "10.0.0.1",
        "172.16.254.1",
        "0.0.0.0",          # lowest octet
        "255.255.255.255",  # highest valid octets
        "01.02.03.04",      # leading zeros are accepted
        "00.00.00.00",
        "8.8.8.8",
        "127.0.0.1",
    ],
)
def test_ipv4_valid_detected_whole(filt, text):
    spans = filt.detect(text)
    assert len(spans) == 1
    span = spans[0]
    assert span.text == text
    assert span.character_start == 0
    assert span.character_end == len(text)
    assert span.filter_type == "ip-address"
    assert span.confidence == 1.0
    assert span.replacement == ""


def test_ipv4_in_sentence_offsets(filt):
    text = "My IP is 192.168.1.1 here"
    spans = filt.detect(text)
    assert len(spans) == 1
    span = spans[0]
    assert span.text == "192.168.1.1"
    assert span.character_start == 9
    assert span.character_end == 20
    assert text[span.character_start:span.character_end] == "192.168.1.1"


def test_multiple_ipv4_in_text(filt):
    text = "10.0.0.1 and 172.16.254.1"
    spans = filt.detect(text)
    assert len(spans) == 2
    assert spans[0].text == "10.0.0.1"
    assert spans[0].character_start == 0
    assert spans[0].character_end == 8
    assert spans[1].text == "172.16.254.1"
    assert spans[1].character_start == 13
    assert spans[1].character_end == 25
    assert all(s.filter_type == "ip-address" for s in spans)


# ---------------------------------------------------------------------------
# Positive IPv6 cases
# ---------------------------------------------------------------------------

def test_ipv6_full_eight_groups(filt):
    text = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    spans = filt.detect(text)
    assert len(spans) == 1
    span = spans[0]
    assert span.text == text
    assert span.character_start == 0
    assert span.character_end == len(text)
    assert span.filter_type == "ip-address"
    assert span.confidence == 1.0


def test_ipv6_full_with_letters_lowercase(filt):
    text = "fe80:0:0:0:0:0:0:1"
    spans = filt.detect(text)
    assert len(spans) == 1
    assert spans[0].text == text


@pytest.mark.parametrize(
    "text, expected",
    [
        # The compressed pattern requires a word boundary after the trailing
        # "::", so it only matches when followed by another hex group.
        ("2001:db8::1234", "2001:db8::"),
        (" 2001:db8::1 ", "2001:db8::"),
    ],
)
def test_ipv6_compressed_trailing_double_colon(filt, text, expected):
    spans = filt.detect(text)
    assert len(spans) == 1
    span = spans[0]
    assert span.text == expected
    assert span.filter_type == "ip-address"
    assert span.confidence == 1.0
    assert text[span.character_start:span.character_end] == expected


# ---------------------------------------------------------------------------
# Negative IPv4 cases
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "text",
    [
        "256.1.1.1",          # first octet > 255
        "999.999.999.999",    # all octets out of range
        "300.300.300.300",
        "256.256.256.256",
        "1.2.3",              # too few octets
        "not an ip 1234",     # plain number
        "hello world",        # no digits/colons
        "",                   # empty
    ],
)
def test_ipv4_invalid_not_detected(filt, text):
    assert filt.detect(text) == []


def test_octet_over_255_octet_skipped_but_valid_neighbor_found(filt):
    text = "256.256.256.256 but 1.2.3.4 ok"
    spans = filt.detect(text)
    assert len(spans) == 1
    assert spans[0].text == "1.2.3.4"
    assert spans[0].character_start == 20


def test_too_many_octets_matches_first_four(filt):
    # A run of five octets still yields the first valid dotted-quad.
    text = "1.2.3.4.5.6"
    spans = filt.detect(text)
    assert len(spans) == 1
    assert spans[0].text == "1.2.3.4"
    assert spans[0].character_start == 0
    assert spans[0].character_end == 7


# ---------------------------------------------------------------------------
# Negative IPv6 cases
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "text",
    [
        "2001:db8::",     # trailing "::" with no following group -> no \b match
        "fe80::",         # bare compressed, nothing after
        "2001:db8:: ",    # trailing "::" before a space, still no match
    ],
)
def test_ipv6_not_detected(filt, text):
    assert filt.detect(text) == []


# ---------------------------------------------------------------------------
# Construction / config
# ---------------------------------------------------------------------------

def test_default_config_is_empty_dict():
    assert IPAddressFilter().config == {}


def test_none_config_normalized_to_empty_dict():
    assert IPAddressFilter(None).config == {}


def test_filter_type_attribute():
    assert IPAddressFilter().filter_type == "ip-address"


def test_context_passed_through(filt):
    spans = filt.detect("192.168.1.1", context="custom")
    assert len(spans) == 1
    assert spans[0].context == "custom"
