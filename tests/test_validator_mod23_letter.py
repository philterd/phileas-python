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

"""mod-23 control-letter parity tests (mirrors the Phileas Java Mod23LetterValidatorTest)."""

from phileas.filters.identifier_validators.mod23_letter import (
    is_valid,
    DEFAULT_PREFIX_SUBSTITUTIONS,
)
from phileas.filters.validators import resolve_validator

SUBS = DEFAULT_PREFIX_SUBSTITUTIONS


def test_registered():
    assert resolve_validator("mod23-letter")("12345678Z") is True


def test_valid_dni():
    assert is_valid("12345678Z", SUBS) is True


def test_invalid_dni_letter():
    assert is_valid("12345678A", SUBS) is False


def test_valid_nie_x():
    assert is_valid("X1234567L", SUBS) is True


def test_valid_nie_y():
    assert is_valid("Y1234567X", SUBS) is True


def test_invalid_nie_letter():
    assert is_valid("X1234567A", SUBS) is False


def test_case_insensitive():
    assert is_valid("12345678z", SUBS) is True


def test_wrong_length():
    assert is_valid("1234567Z", SUBS) is False


def test_control_must_be_letter():
    assert is_valid("123456781", SUBS) is False


def test_dni_with_non_digits_is_invalid():
    assert is_valid("1234A678Z", SUBS) is False


def test_none_is_invalid():
    assert is_valid(None, SUBS) is False
