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
        # A compressed address is covered in full, not just up to its "::".
        ("2001:db8::1234", "2001:db8::1234"),
        (" 2001:db8::1 ", "2001:db8::1"),
        ("FE80::1", "FE80::1"),
        ("2001:db8:85a3::8a2e:370:7334", "2001:db8:85a3::8a2e:370:7334"),
        ("fe80::0202:B3FF:FE1E:8329", "fe80::0202:B3FF:FE1E:8329"),
        # Leading "::" was not detected at all before.
        ("::1", "::1"),
        ("::", "::"),
        # Trailing "::" with nothing after it.
        ("2001:db8::", "2001:db8::"),
        ("fe80::", "fe80::"),
        ("1::", "1::"),
        # IPv4-mapped: the "::ffff:" prefix was left in the clear.
        ("::ffff:192.0.2.128", "::ffff:192.0.2.128"),
        ("::ffff:0:192.0.2.128", "::ffff:0:192.0.2.128"),
        # Six hextets and a dotted quad.
        ("1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:1.2.3.4"),
        # A zone identifier belongs to the address.
        ("fe80::1%eth0", "fe80::1%eth0"),
        ("fe80::1%25eth0", "fe80::1%25eth0"),
    ],
)
def test_ipv6_forms_detected_whole(filt, text, expected):
    spans = filt.detect(text)
    assert len(spans) == 1
    span = spans[0]
    assert span.text == expected
    assert span.filter_type == "ip-address"
    assert span.confidence == 1.0
    assert text[span.character_start:span.character_end] == expected


@pytest.mark.parametrize(
    "text, expected, start",
    [
        ("host FE80::1", "FE80::1", 5),
        ("host 2001:db8:85a3::8a2e:370:7334", "2001:db8:85a3::8a2e:370:7334", 5),
        ("host ::1", "::1", 5),
        ("host ::ffff:192.0.2.128", "::ffff:192.0.2.128", 5),
        ("host fe80::1%eth0", "fe80::1%eth0", 5),
        ("http://[2001:db8::1]:8080/x", "2001:db8::1", 8),
        # A trailing sentence period is left out of the span.
        ("the ip is 2001:db8::1.", "2001:db8::1", 10),
    ],
)
def test_ipv6_in_sentence_offsets(filt, text, expected, start):
    spans = filt.detect(text)
    assert len(spans) == 1
    span = spans[0]
    assert span.text == expected
    assert span.character_start == start
    assert span.character_end == start + len(expected)
    assert text[span.character_start:span.character_end] == expected


def test_multiple_ipv6_in_text(filt):
    text = "FE80::1 and ::ffff:192.0.2.128"
    spans = filt.detect(text)
    assert len(spans) == 2
    assert spans[0].text == "FE80::1"
    assert spans[0].character_start == 0
    assert spans[1].text == "::ffff:192.0.2.128"
    assert spans[1].character_start == 12


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
        "meeting at 12:30 today",    # a time is not an address
        "the score was 3:2",
        "Time 10:30:45 UTC",
        "00:1A:2B:3C:4D:5E",         # a MAC address is not an address
        "00-1A-2B-3C-4D-5E",
        "a1:b2",                     # two hextets and no "::"
        "no address here",
    ],
)
def test_ipv6_not_detected(filt, text):
    assert filt.detect(text) == []


@pytest.mark.parametrize(
    "text",
    [
        # A "::" inside a longer word is scope resolution, not an address. Without a boundary on
        # each side these matched a fragment ("d::" out of "std::vector").
        "std::vector<int> v;",
        "use namespace foo::bar",
        "Employee::getName()",
        "key=value::pair",
        "note: ::before and ::after",
        "Error at line 12: bad::thing",
        "a::bcdefg",                 # too many hex characters to be a hextet
    ],
)
def test_scope_resolution_not_detected(filt, text):
    assert filt.detect(text) == []


@pytest.mark.parametrize(
    "text, expected, start",
    [
        # The boundary is on word characters, so punctuation around an address does not hide it.
        ("IPv6:2001:db8::1", "2001:db8::1", 5),
        ("addr=fe80::1 end", "fe80::1", 5),
        ("(2001:db8::1)", "2001:db8::1", 1),
        ("2001:db8::1/64", "2001:db8::1", 0),
    ],
)
def test_ipv6_adjacent_punctuation(filt, text, expected, start):
    spans = filt.detect(text)
    assert len(spans) == 1
    assert spans[0].text == expected
    assert spans[0].character_start == start


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
