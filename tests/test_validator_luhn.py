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

"""Luhn validator parity tests (mirrors the Phileas Java LuhnValidatorTest)."""

from phileas.filters.identifier_validators.luhn import is_valid
from phileas.filters.validators import resolve_validator


def test_registered():
    assert resolve_validator("luhn")("046454286") is True


def test_valid_sin_unformatted():
    assert is_valid("046454286") is True


def test_valid_sin_space_separated():
    assert is_valid("046 454 286") is True


def test_valid_sin_hyphenated():
    assert is_valid("046-454-286") is True


def test_invalid_sin_checksum():
    assert is_valid("046454287") is False


def test_looks_like_sin_but_fails():
    assert is_valid("123456789") is False


def test_valid_credit_card():
    assert is_valid("4111111111111111") is True


def test_invalid_credit_card():
    assert is_valid("4111111111111112") is False


def test_doubling_over_nine():
    assert is_valid("91") is True


def test_none_empty_no_digits():
    assert is_valid(None) is False
    assert is_valid("") is False
    assert is_valid("---") is False


def test_separators_ignored():
    assert is_valid(" 046-454 286 ") is True
