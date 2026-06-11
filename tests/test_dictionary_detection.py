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

from phileas.filters.dictionary_filter import BloomFilter, DictionaryFilter


def make_filter(terms):
    return DictionaryFilter({"classification": "org", "terms": terms})


# ---------------------------------------------------------------------------
# Multi-term matching
# ---------------------------------------------------------------------------
def test_multiple_terms_all_detected():
    f = make_filter(["apple", "banana", "cherry"])
    spans = f.detect("apple and banana then cherry")
    assert len(spans) == 3
    assert [s.text for s in spans] == ["apple", "banana", "cherry"]


def test_multiple_terms_offsets_correct():
    f = make_filter(["apple", "banana", "cherry"])
    text = "apple and banana then cherry"
    spans = f.detect(text)
    for s in spans:
        assert text[s.character_start:s.character_end] == s.text


def test_single_term_repeated_matches():
    f = make_filter(["acme"])
    text = "acme then acme again"
    spans = f.detect(text)
    assert len(spans) == 2
    assert all(s.text == "acme" for s in spans)
    assert spans[0].character_start == 0
    assert spans[1].character_start == 10


def test_term_not_present_yields_no_spans():
    f = make_filter(["apple", "banana"])
    assert f.detect("there is no fruit here") == []


# ---------------------------------------------------------------------------
# Case-insensitive matching
# ---------------------------------------------------------------------------
CASE_VARIANTS = [
    "cat",
    "CAT",
    "Cat",
    "cAt",
    "CaT",
]


@pytest.mark.parametrize("variant", CASE_VARIANTS)
def test_case_insensitive_matching(variant):
    f = make_filter(["cat"])
    spans = f.detect(variant)
    assert len(spans) == 1
    # The matched text preserves the original casing from the input.
    assert spans[0].text == variant


def test_case_insensitive_term_definition():
    # Term defined uppercase, text lowercase still matches.
    f = make_filter(["ACME"])
    spans = f.detect("the acme corp")
    assert len(spans) == 1
    assert spans[0].text == "acme"


# ---------------------------------------------------------------------------
# Word-boundary behavior: a substring of a longer word must NOT match
# ---------------------------------------------------------------------------
NON_MATCHING_SUBSTRINGS = [
    "catalog",     # 'cat' as prefix
    "scatter",     # 'cat' in middle
    "bobcat",      # 'cat' as suffix
    "cats",        # plural -> trailing word char
    "concatenate",
]


@pytest.mark.parametrize("text", NON_MATCHING_SUBSTRINGS)
def test_substring_of_longer_word_not_matched(text):
    f = make_filter(["cat"])
    assert f.detect(text) == []


def test_word_boundary_standalone_matches():
    f = make_filter(["cat"])
    spans = f.detect("a cat sat")
    assert len(spans) == 1
    assert spans[0].text == "cat"
    assert spans[0].character_start == 2
    assert spans[0].character_end == 5


PUNCTUATION_BOUNDARIES = [
    "cat-dog",
    "cat.",
    "(cat)",
    "cat,here",
    "say:cat",
]


@pytest.mark.parametrize("text", PUNCTUATION_BOUNDARIES)
def test_punctuation_acts_as_boundary(text):
    # Non-word characters are valid boundaries, so the term still matches.
    f = make_filter(["cat"])
    spans = f.detect(text)
    assert len(spans) == 1
    assert spans[0].text == "cat"


# ---------------------------------------------------------------------------
# Longest-term-wins among overlapping terms
# ---------------------------------------------------------------------------
def test_longest_term_wins_overlap():
    f = make_filter(["New York", "New York City"])
    text = "I love New York City"
    spans = f.detect(text)
    assert len(spans) == 1
    assert spans[0].text == "New York City"
    assert text[spans[0].character_start:spans[0].character_end] == "New York City"


def test_longest_term_wins_regardless_of_order():
    # Same as above but terms supplied in the opposite order.
    f = make_filter(["New York City", "New York"])
    spans = f.detect("near New York City today")
    assert len(spans) == 1
    assert spans[0].text == "New York City"


def test_shorter_term_matches_when_longer_absent():
    f = make_filter(["New York", "New York City"])
    spans = f.detect("welcome to New York please")
    assert len(spans) == 1
    assert spans[0].text == "New York"


# ---------------------------------------------------------------------------
# Empty terms -> no spans
# ---------------------------------------------------------------------------
def test_empty_terms_list_no_spans():
    f = make_filter([])
    assert f.detect("apple banana cat") == []


def test_terms_key_missing_no_spans():
    f = DictionaryFilter({"classification": "org"})
    assert f.detect("apple banana cat") == []


def test_none_terms_value_no_spans():
    f = DictionaryFilter({"classification": "org", "terms": None})
    assert f.detect("apple banana cat") == []


# ---------------------------------------------------------------------------
# filter_type equals the classification
# ---------------------------------------------------------------------------
def test_filter_type_equals_classification():
    f = make_filter(["apple"])
    spans = f.detect("apple")
    assert len(spans) == 1
    assert spans[0].filter_type == "org"
    assert f.filter_type == "org"


def test_custom_classification_used_as_filter_type():
    f = DictionaryFilter({"classification": "company-name", "terms": ["apple"]})
    spans = f.detect("apple")
    assert spans[0].filter_type == "company-name"


def test_default_classification_when_none():
    # No classification -> falls back to the dictionary filter type.
    f = DictionaryFilter(None)
    assert f.filter_type == "dictionary"


def test_default_construction_no_config():
    f = DictionaryFilter()
    assert f.detect("anything") == []


# ---------------------------------------------------------------------------
# Span attribute details
# ---------------------------------------------------------------------------
def test_span_confidence_and_replacement():
    f = make_filter(["apple"])
    span = f.detect("apple")[0]
    assert span.confidence == 1.0
    assert span.replacement == ""


def test_context_argument_propagated():
    f = make_filter(["apple"])
    span = f.detect("apple", context="custom")[0]
    assert span.context == "custom"


def test_context_defaults_to_default():
    f = make_filter(["apple"])
    span = f.detect("apple")[0]
    assert span.context == "default"


# ---------------------------------------------------------------------------
# BloomFilter direct exercise
# ---------------------------------------------------------------------------
def test_bloom_add_and_contains():
    b = BloomFilter(capacity=100)
    b.add("hello")
    assert "hello" in b


@pytest.mark.parametrize(
    "item",
    ["alpha", "beta", "gamma", "delta", "epsilon", "term with spaces", "MixedCase"],
)
def test_bloom_no_false_negatives(item):
    b = BloomFilter(capacity=50)
    for word in ["alpha", "beta", "gamma", "delta", "epsilon",
                 "term with spaces", "MixedCase"]:
        b.add(word)
    # Every added item must report present (no false negatives).
    assert item in b


def test_bloom_unadded_item_absent():
    b = BloomFilter(capacity=100)
    b.add("present")
    assert "definitely-not-added-xyz-123" not in b


def test_bloom_non_string_returns_false():
    b = BloomFilter(capacity=10)
    b.add("x")
    assert (5 in b) is False
    assert (None in b) is False
    assert (object() in b) is False


def test_bloom_empty_filter_contains_nothing():
    b = BloomFilter(capacity=10)
    assert "anything" not in b


def test_bloom_many_items_no_false_negatives():
    items = [f"item-{i}" for i in range(200)]
    b = BloomFilter(capacity=len(items))
    for it in items:
        b.add(it)
    for it in items:
        assert it in b


def test_bloom_capacity_zero_safe():
    # Capacity is clamped to at least 1 internally.
    b = BloomFilter(capacity=0)
    b.add("x")
    assert "x" in b
