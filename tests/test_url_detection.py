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

"""Detection tests for the URLFilter filter."""

import pytest

from phileas.filters.url_filter import URLFilter


@pytest.fixture
def url_filter():
    return URLFilter()


# ---------------------------------------------------------------------------
# Positive cases: the extracted URL text and offsets
# ---------------------------------------------------------------------------

POSITIVE_CASES = [
    # (text, expected_url_substring)
    ("Visit http://example.com today", "http://example.com"),
    ("Go to https://example.com/path/to/page now", "https://example.com/path/to/page"),
    ("Query https://example.com/search?q=hello&page=2 ok",
     "https://example.com/search?q=hello&page=2"),
    ("Frag https://example.com/page#section ok", "https://example.com/page#section"),
    ("Both https://example.com/path?q=1#frag end", "https://example.com/path?q=1#frag"),
    ("Percent https://example.com/a%20b/c%2Fd ok", "https://example.com/a%20b/c%2Fd"),
    ("HTTP://EXAMPLE.COM/PATH at start", "HTTP://EXAMPLE.COM/PATH"),
    ("Deep https://sub.domain.example.co.uk/a/b/c here",
     "https://sub.domain.example.co.uk/a/b/c"),
    ("Local http://localhost end", "http://localhost"),
]


@pytest.mark.parametrize("text,expected", POSITIVE_CASES)
def test_positive_detects_url(url_filter, text, expected):
    spans = url_filter.detect(text)
    assert len(spans) == 1
    span = spans[0]
    assert span.text == expected
    # Offsets must point back at exactly the matched substring.
    assert text[span.character_start:span.character_end] == expected
    assert span.character_start == text.index(expected)
    assert span.character_end == text.index(expected) + len(expected)


@pytest.mark.parametrize("text,expected", POSITIVE_CASES)
def test_positive_span_metadata(url_filter, text, expected):
    span = url_filter.detect(text)[0]
    assert span.filter_type == "url"
    assert span.confidence == 1.0
    # detect() always returns an empty replacement.
    assert span.replacement == ""


# ---------------------------------------------------------------------------
# Negative cases: no URL should be detected
# ---------------------------------------------------------------------------

NEGATIVE_CASES = [
    "ftp://files.example.com/file.txt",
    "just example.com bare",
    "no urls plain text here",
    "www.example.com without scheme",
    "Email user@example.com here",
    "mailto:someone@example.com",
    "Path /usr/local/bin without host",
    "scheme is missing //example.com/path",
    "",
    "   ",
]


@pytest.mark.parametrize("text", NEGATIVE_CASES)
def test_negative_no_detection(url_filter, text):
    assert url_filter.detect(text) == []


# ---------------------------------------------------------------------------
# Scheme requirement
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("scheme,expected_count", [
    ("http", 1),
    ("https", 1),
    ("HTTP", 1),
    ("HTTPS", 1),
    ("ftp", 0),
    ("file", 0),
    ("ws", 0),
    ("gopher", 0),
])
def test_scheme_handling(url_filter, scheme, expected_count):
    text = f"go {scheme}://example.com/path here"
    assert len(url_filter.detect(text)) == expected_count


# ---------------------------------------------------------------------------
# Port behavior: a port and everything after it belong to the URL.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    # A port with a path. The path is what was left in the document before.
    ("Port http://example.com:8080/path here", "http://example.com:8080/path"),
    ("https://portal.hospital.org:8443/patient/12345",
     "https://portal.hospital.org:8443/patient/12345"),
    ("http://example.com:8080/path/secret", "http://example.com:8080/path/secret"),
    # A port with no path.
    ("Port only http://example.com:8080 here", "http://example.com:8080"),
    ("http://localhost:3000", "http://localhost:3000"),
    ("http://localhost:3000/", "http://localhost:3000/"),
    # A port with a query or a fragment.
    ("http://example.com:80?q=1", "http://example.com:80?q=1"),
    ("http://example.com:443#top", "http://example.com:443#top"),
    ("https://example.com:8443/a/b?q=1#frag", "https://example.com:8443/a/b?q=1#frag"),
    # The bounds of the port itself.
    ("http://a.com:1", "http://a.com:1"),
    ("http://a.com:65535", "http://a.com:65535"),
])
def test_port_captured(url_filter, text, expected):
    spans = url_filter.detect(text)
    assert len(spans) == 1
    assert spans[0].text == expected
    assert text[spans[0].character_start:spans[0].character_end] == expected


@pytest.mark.parametrize("text,expected", [
    # Digits are required after the colon, so sentence punctuation does not extend the match.
    ("Visit http://example.com: the time is 12:30", "http://example.com"),
    ("Note http://example.com:8080: the port is odd", "http://example.com:8080"),
    ("http://example.com:abc/path", "http://example.com"),
    ("http://example.com:/path", "http://example.com"),
    ("Link http://example.com:: odd", "http://example.com"),
])
def test_colon_that_is_not_a_port_does_not_extend_match(url_filter, text, expected):
    spans = url_filter.detect(text)
    assert len(spans) == 1
    assert spans[0].text == expected


def test_port_longer_than_five_digits_truncates(url_filter):
    # Characterization: the port is bounded at five digits, matching the Java port, so a longer
    # run of digits is not consumed in full. No valid port exceeds 65535.
    spans = url_filter.detect("http://a.com:123456")
    assert len(spans) == 1
    assert spans[0].text == "http://a.com:12345"


def test_two_urls_with_ports(url_filter):
    spans = url_filter.detect("A http://a.com:1/x B http://b.com:2/y")
    assert [s.text for s in spans] == ["http://a.com:1/x", "http://b.com:2/y"]


# ---------------------------------------------------------------------------
# Multiple URLs in one string
# ---------------------------------------------------------------------------

def test_multiple_urls(url_filter):
    text = "Two http://a.com and https://b.org/p here"
    spans = url_filter.detect(text)
    found = {s.text for s in spans}
    assert found == {"http://a.com", "https://b.org/p"}
    assert len(spans) == 2


def test_only_http_https_among_mixed_schemes(url_filter):
    text = "ftp test ftp://x.com but http://y.com too"
    spans = url_filter.detect(text)
    assert len(spans) == 1
    assert spans[0].text == "http://y.com"


# ---------------------------------------------------------------------------
# Query, fragment, and percent-encoding details
# ---------------------------------------------------------------------------

def test_query_with_multiple_params(url_filter):
    text = "https://example.com/api?a=1&b=2&c=3"
    span = url_filter.detect(text)[0]
    assert span.text == "https://example.com/api?a=1&b=2&c=3"


def test_fragment_only(url_filter):
    text = "https://example.com#top"
    span = url_filter.detect(text)[0]
    assert span.text == "https://example.com#top"


def test_percent_encoded_query(url_filter):
    text = "https://example.com/s?q=a%20b%26c"
    span = url_filter.detect(text)[0]
    assert span.text == "https://example.com/s?q=a%20b%26c"


def test_trailing_period_included_in_host(url_filter):
    # The host charset includes '.', so a sentence-ending period adjacent to a
    # bare-host URL is captured as part of the match.
    text = "See http://example.com."
    span = url_filter.detect(text)[0]
    assert span.text == "http://example.com."


# ---------------------------------------------------------------------------
# Config construction variants
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("config", [None, {}])
def test_construct_with_config(config):
    f = URLFilter(config)
    spans = f.detect("visit https://example.com/x now")
    assert len(spans) == 1
    assert spans[0].filter_type == "url"


def test_context_argument_accepted(url_filter):
    spans = url_filter.detect("https://example.com/a", context="custom")
    assert len(spans) == 1
    assert spans[0].text == "https://example.com/a"
