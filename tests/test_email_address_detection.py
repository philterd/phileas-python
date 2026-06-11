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

from phileas.filters.email_address_filter import EmailAddressFilter


@pytest.fixture
def email_filter():
    return EmailAddressFilter()


# ---------------------------------------------------------------------------
# Positive cases: text -> expected matched email substring
# ---------------------------------------------------------------------------
POSITIVE_CASES = [
    # basic
    ("a@b.com", "a@b.com"),
    ("john.doe@example.com", "john.doe@example.com"),
    # subdomains / multi-level domains
    ("user@sub.domain.co.uk", "user@sub.domain.co.uk"),
    ("a@b.c.com", "a@b.c.com"),
    ("a.b.c@d.e.f.com", "a.b.c@d.e.f.com"),
    # dashes in local part and domain
    ("first-last@my-domain.com", "first-last@my-domain.com"),
    ("support@help.example-site.co", "support@help.example-site.co"),
    ("dash-@x.com", "dash-@x.com"),
    # underscores and dots in local part
    ("a_b@c.com", "a_b@c.com"),
    # numeric local part
    ("num123@test.io", "num123@test.io"),
    # uppercase
    ("MARY.SMITH@EXAMPLE.COM", "MARY.SMITH@EXAMPLE.COM"),
    # TLD lengths 2-4
    ("x@y.ab", "x@y.ab"),
    ("x@y.abc", "x@y.abc"),
    ("x@y.abcd", "x@y.abcd"),
    (".start@x.com", "start@x.com"),
]


@pytest.mark.parametrize("text,expected", POSITIVE_CASES)
def test_positive_detection(email_filter, text, expected):
    spans = email_filter.detect(text)
    assert len(spans) == 1
    assert spans[0].text == expected


@pytest.mark.parametrize("text,expected", POSITIVE_CASES)
def test_positive_filter_type(email_filter, text, expected):
    spans = email_filter.detect(text)
    assert spans[0].filter_type == "email-address"


@pytest.mark.parametrize("text,expected", POSITIVE_CASES)
def test_positive_confidence(email_filter, text, expected):
    spans = email_filter.detect(text)
    assert spans[0].confidence == 1.0


@pytest.mark.parametrize("text,expected", POSITIVE_CASES)
def test_positive_replacement_empty(email_filter, text, expected):
    spans = email_filter.detect(text)
    assert spans[0].replacement == ""


@pytest.mark.parametrize("text,expected", POSITIVE_CASES)
def test_positive_offsets(email_filter, text, expected):
    spans = email_filter.detect(text)
    span = spans[0]
    assert text[span.character_start:span.character_end] == expected


# ---------------------------------------------------------------------------
# Negative cases: no email should be detected
# ---------------------------------------------------------------------------
NEGATIVE_CASES = [
    "@b.com",        # missing local part
    "a@",            # missing domain
    "plain text",    # no email at all
    "user@nodot",    # missing TLD / no dot
    "name@host.x",   # single-char TLD
    "",              # empty string
    "no at sign here.com",
    "just.some.dotted.text",
]


@pytest.mark.parametrize("text", NEGATIVE_CASES)
def test_negative_detection(email_filter, text):
    spans = email_filter.detect(text)
    assert spans == []


# ---------------------------------------------------------------------------
# Embedded / contextual cases
# ---------------------------------------------------------------------------
def test_embedded_in_sentence(email_filter):
    text = "Contact john.doe@example.com please"
    spans = email_filter.detect(text)
    assert len(spans) == 1
    span = spans[0]
    assert span.text == "john.doe@example.com"
    assert span.character_start == 8
    assert span.character_end == 28
    assert text[span.character_start:span.character_end] == "john.doe@example.com"


def test_multiple_emails_in_text(email_filter):
    text = "two a@b.com and c@d.org here"
    spans = email_filter.detect(text)
    assert len(spans) == 2
    assert {s.text for s in spans} == {"a@b.com", "c@d.org"}
    for s in spans:
        assert s.filter_type == "email-address"
        assert text[s.character_start:s.character_end] == s.text


def test_plus_addressing_starts_after_plus(email_filter):
    # The '+' character is not part of the recognized local-part character
    # class, so detection begins after the '+'.
    text = "user+tag@gmail.com"
    spans = email_filter.detect(text)
    assert len(spans) == 1
    assert spans[0].text == "tag@gmail.com"


def test_long_tld_still_matches(email_filter):
    # Domains with TLDs longer than 4 characters (e.g. .museum) are matched.
    text = "a@b.museum"
    spans = email_filter.detect(text)
    assert len(spans) == 1
    assert spans[0].text == "a@b.museum"


def test_context_argument_accepted(email_filter):
    spans = email_filter.detect("a@b.com", context="custom")
    assert len(spans) == 1
    assert spans[0].text == "a@b.com"


def test_default_config_construction():
    f = EmailAddressFilter()
    spans = f.detect("a@b.com")
    assert len(spans) == 1
    assert spans[0].filter_type == "email-address"
