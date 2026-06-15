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

"""German Steuer-ID parity tests (mirrors the Phileas Java DeSteuerIdValidatorTest)."""

from phileas.filters.identifier_validators.de_steuerid import is_valid
from phileas.filters.validators import resolve_validator


def test_registered():
    assert resolve_validator("de-steuerid")("86095742719") is True


def test_valid_repeated_twice():
    assert is_valid("86095742719") is True


def test_valid_repeated_three_times():
    assert is_valid("65929970489") is True


def test_valid_different_check_digit():
    assert is_valid("47036892816") is True


def test_valid_with_separators():
    assert is_valid("86 095 742 719") is True


def test_wrong_check_digit():
    assert is_valid("86095742718") is False


def test_no_repeated_digit_fails_structure():
    assert is_valid("12345678905") is False


def test_two_different_digits_repeated_fails_structure():
    assert is_valid("11223456780") is False


def test_digit_repeated_four_times_fails_structure():
    assert is_valid("11110234567") is False


def test_leading_zero_is_invalid():
    assert is_valid("01234567890") is False


def test_wrong_length():
    assert is_valid("8609574271") is False
    assert is_valid("860957427190") is False


def test_letters_are_invalid():
    assert is_valid("8609574271A") is False


def test_none_and_empty():
    assert is_valid(None) is False
    assert is_valid("") is False
