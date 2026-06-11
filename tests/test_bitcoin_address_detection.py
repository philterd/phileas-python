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

from phileas.filters.bitcoin_address_filter import BitcoinAddressFilter


FILTER_TYPE = "bitcoin-address"


@pytest.fixture
def filt():
    return BitcoinAddressFilter()


# ---------------------------------------------------------------------------
# Positive cases
# ---------------------------------------------------------------------------

REAL_ADDRESSES = [
    # Legacy P2PKH (starts with 1)
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
    # P2SH (starts with 3)
    "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
    "3P14159f73E4gFr7JterCCQh9QjiTjiZrG",
    # Bech32 (starts with bc1)
    "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
]


@pytest.mark.parametrize("address", REAL_ADDRESSES)
def test_detects_real_addresses(filt, address):
    spans = filt.detect(address)
    assert len(spans) == 1
    assert spans[0].text == address


@pytest.mark.parametrize("address", REAL_ADDRESSES)
def test_span_attributes(filt, address):
    span = filt.detect(address)[0]
    assert span.filter_type == FILTER_TYPE
    assert span.character_start == 0
    assert span.character_end == len(address)
    assert span.confidence == 1.0
    # detect() never sets a replacement
    assert span.replacement == ""


def test_p2pkh_minimum_length(filt):
    # 1 + 25 trailing chars = 26 total is the minimum that matches
    addr = "1" + "a" * 25
    spans = filt.detect(addr)
    assert len(spans) == 1
    assert spans[0].text == addr


def test_p2pkh_maximum_length(filt):
    # 1 + 34 trailing chars = 35 total is the maximum that matches
    addr = "1" + "a" * 34
    spans = filt.detect(addr)
    assert len(spans) == 1
    assert spans[0].text == addr


def test_p2sh_minimum_length(filt):
    addr = "3" + "a" * 25
    spans = filt.detect(addr)
    assert len(spans) == 1
    assert spans[0].text == addr


def test_p2sh_maximum_length(filt):
    addr = "3" + "a" * 34
    spans = filt.detect(addr)
    assert len(spans) == 1
    assert spans[0].text == addr


def test_bech32_minimum_length(filt):
    # bc1 + 39 trailing chars
    addr = "bc1" + "q" * 39
    spans = filt.detect(addr)
    assert len(spans) == 1
    assert spans[0].text == addr


def test_bech32_maximum_length(filt):
    # bc1 + 59 trailing chars
    addr = "bc1" + "q" * 59
    spans = filt.detect(addr)
    assert len(spans) == 1
    assert spans[0].text == addr


def test_address_in_sentence(filt):
    text = "Send funds to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa today."
    spans = filt.detect(text)
    assert len(spans) == 1
    assert spans[0].text == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    assert spans[0].character_start == 14
    assert text[spans[0].character_start : spans[0].character_end] == spans[0].text


def test_bech32_in_sentence_offsets(filt):
    addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
    text = "abc " + addr + " def"
    spans = filt.detect(text)
    assert len(spans) == 1
    assert spans[0].character_start == 4
    assert spans[0].character_end == 4 + len(addr)
    assert spans[0].text == addr


def test_multiple_addresses(filt):
    a = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    b = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
    c = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
    text = f"{a} and {b} and {c}"
    spans = filt.detect(text)
    found = {s.text for s in spans}
    assert found == {a, b, c}
    assert len(spans) == 3


def test_returns_list(filt):
    result = filt.detect("no addresses here")
    assert isinstance(result, list)
    assert result == []


def test_context_passed_through(filt):
    addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    spans = filt.detect(addr, context="ctx-name")
    assert len(spans) == 1
    assert spans[0].context == "ctx-name"


def test_default_config_none():
    # Constructing with explicit None behaves the same as default {}
    f = BitcoinAddressFilter(None)
    addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    assert len(f.detect(addr)) == 1


# ---------------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------------

NEGATIVE_CASES = [
    "",
    "not a bitcoin address",
    "1234567890",
    # P2PKH one char too short (1 + 24 = 25 total)
    "1" + "a" * 24,
    # P2PKH one char too long (1 + 35 = 36 total)
    "1" + "a" * 35,
    # P2SH one char too short
    "3" + "a" * 24,
    # P2SH one char too long
    "3" + "a" * 35,
    # Bech32 one char too short (bc1 + 38)
    "bc1" + "q" * 38,
    # Bech32 one char too long (bc1 + 60)
    "bc1" + "q" * 60,
    # Wrong leading digit (2 is not a valid prefix here)
    "2" + "a" * 30,
    # Uppercase bech32 not matched (pattern is lowercase only)
    "BC1QAR0SRRR7XFKVY5L643LYDNW9RE59GTZZWF5MDQ",
    # Only forbidden base58 chars 0 O I l
    "10OIl",
]


@pytest.mark.parametrize("text", NEGATIVE_CASES)
def test_negative_no_detection(filt, text):
    assert filt.detect(text) == []


def test_p2pkh_with_forbidden_zero(filt):
    # base58 excludes '0'; address containing only valid chars but length-OK
    # except one forbidden char => the forbidden char breaks the run.
    addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv0DivfNa"  # contains a '0'
    assert filt.detect(addr) == []


def test_p2pkh_with_forbidden_capital_o(filt):
    addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNO"  # ends with 'O'
    spans = filt.detect(addr)
    # The trailing 'O' is excluded; remaining run is one char short, so
    # nothing should be detected for this 34-char string.
    assert spans == []


def test_bech32_with_forbidden_uppercase_char(filt):
    addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdQ"  # trailing uppercase Q
    assert filt.detect(addr) == []


def test_embedded_in_longer_word_not_matched(filt):
    # A valid-looking address glued to letters on both sides has no word
    # boundary, so it is not detected.
    addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    text = "xxx" + addr + "yyy"
    assert filt.detect(text) == []
