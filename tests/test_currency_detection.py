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

from phileas.filters.currency_filter import CurrencyFilter


FILTER_TYPE = "currency"


@pytest.fixture
def filt():
    return CurrencyFilter()


# ---------------------------------------------------------------------------
# Positive cases: text detected exactly as-is (single span, full string).
# ---------------------------------------------------------------------------

POSITIVE_EXACT = [
    "$100",
    "$1,000.00",
    "$5 million",
    "$ 50",
    "$1,000",
    "$1,000,000",
    "$1000",
    "$100.5",
    "$01",
    "$1,00",
    # Magnitude words (case-insensitive) are part of the match.
    "$5 billion",
    "$5 trillion",
    "$5 thousand",
    "$5 MILLION",
    "$5 Million",
    # A magnitude word with no space before it is still matched.
    "$5million",
]


@pytest.mark.parametrize("text", POSITIVE_EXACT)
def test_detects_exact(filt, text):
    spans = filt.detect(text)
    assert len(spans) == 1
    assert spans[0].text == text
    assert spans[0].character_start == 0
    assert spans[0].character_end == len(text)


@pytest.mark.parametrize("text", POSITIVE_EXACT)
def test_span_attributes(filt, text):
    span = filt.detect(text)[0]
    assert span.filter_type == FILTER_TYPE
    assert span.confidence == 1.0
    # detect() never sets a replacement.
    assert span.replacement == ""
    # The reported offsets map back onto the matched text.
    assert text[span.character_start : span.character_end] == span.text


# ---------------------------------------------------------------------------
# Positive cases where only part of the input is detected.
# ---------------------------------------------------------------------------

PARTIAL_CASES = [
    # Trailing period is not part of the number.
    ("$100.", "$100", 0, 4),
    # "hundred" is not a recognized magnitude word; only "$5" matches.
    ("$5 hundred", "$5", 0, 2),
    # Two spaces break the magnitude word; only "$5" matches.
    ("$5  million", "$5", 0, 2),
    # Trailing dot with nothing after it is dropped.
    ("$1.", "$1", 0, 2),
    # Only the first decimal group is captured.
    ("$1.2.3", "$1.2", 0, 4),
    # Trailing letters are not part of the number.
    ("$100b", "$100", 0, 4),
    # A '$' glued to a preceding letter still matches the amount.
    ("a$100", "$100", 1, 5),
    # "dollars" after a valid magnitude word is excluded.
    ("$5 million dollars", "$5 million", 0, 10),
]


@pytest.mark.parametrize("text,expected,start,end", PARTIAL_CASES)
def test_partial_match(filt, text, expected, start, end):
    spans = filt.detect(text)
    assert len(spans) == 1
    assert spans[0].text == expected
    assert spans[0].character_start == start
    assert spans[0].character_end == end


def test_amount_in_sentence(filt):
    text = "The invoice cost $100 today."
    spans = filt.detect(text)
    assert len(spans) == 1
    assert spans[0].text == "$100"
    assert spans[0].character_start == 17
    assert text[spans[0].character_start : spans[0].character_end] == "$100"


def test_leading_and_trailing_whitespace(filt):
    text = "   $100   "
    spans = filt.detect(text)
    assert len(spans) == 1
    assert spans[0].text == "$100"
    assert spans[0].character_start == 3
    assert spans[0].character_end == 7


def test_space_after_dollar_sign_included(filt):
    # The optional single space after '$' is part of the matched text.
    spans = filt.detect("$ 50")
    assert len(spans) == 1
    assert spans[0].text == "$ 50"


def test_multiple_amounts(filt):
    text = "$100 and $200"
    spans = filt.detect(text)
    assert len(spans) == 2
    assert spans[0].text == "$100"
    assert spans[0].character_start == 0
    assert spans[1].text == "$200"
    assert spans[1].character_start == 9


def test_multiple_amounts_mixed_forms(filt):
    text = "Paid $1,000.00 then $5 million plus $50."
    spans = filt.detect(text)
    texts = [s.text for s in spans]
    assert texts == ["$1,000.00", "$5 million", "$50"]


def test_returns_list(filt):
    result = filt.detect("no amounts here")
    assert isinstance(result, list)
    assert result == []


def test_context_default(filt):
    span = filt.detect("$100")[0]
    assert span.context == "default"


def test_context_passed_through(filt):
    span = filt.detect("$100", context="ctx-name")[0]
    assert span.context == "ctx-name"


def test_default_config_none():
    # Constructing with explicit None behaves the same as default {}.
    f = CurrencyFilter(None)
    spans = f.detect("$100")
    assert len(spans) == 1
    assert spans[0].text == "$100"


def test_default_config_empty_dict():
    f = CurrencyFilter({})
    spans = f.detect("$100")
    assert len(spans) == 1


# ---------------------------------------------------------------------------
# Negative cases: nothing detected.
# ---------------------------------------------------------------------------

NEGATIVE_CASES = [
    "",
    "no amounts here",
    # A plain number without the '$' sign.
    "100",
    "1,000.00",
    "5 million",
    # Spelled-out currency is not detected.
    "100 dollars",
    "USD 100",
    # Other currency symbols are not handled.
    "€100",  # euro
    "£50",   # pound
    "¥100",  # yen
    # A '$' with no digits.
    "$",
    "$ ",
    "the price is $",
    # A decimal with no leading digit after '$'.
    "$.50",
]


@pytest.mark.parametrize("text", NEGATIVE_CASES)
def test_negative_no_detection(filt, text):
    assert filt.detect(text) == []
