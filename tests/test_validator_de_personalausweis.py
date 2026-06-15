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

"""German Personalausweis parity tests (mirrors the Phileas Java test)."""

from phileas.filters.identifier_validators.de_personalausweis import is_valid
from phileas.filters.validators import resolve_validator


def test_registered():
    assert resolve_validator("de-personalausweis")("T220001293") is True


def test_valid_number():
    assert is_valid("T220001293") is True


def test_valid_number_second_vector():
    assert is_valid("M123456788") is True


def test_case_insensitive():
    assert is_valid("t220001293") is True


def test_surrounding_whitespace_ignored():
    assert is_valid("  T220001293  ") is True


def test_wrong_check_digit():
    assert is_valid("T220001294") is False


def test_altered_serial_fails_check():
    assert is_valid("T220001393") is False


def test_check_digit_must_be_a_digit():
    assert is_valid("T22000129X") is False


def test_invalid_character_in_serial():
    assert is_valid("T2200012*3") is False


def test_wrong_length():
    assert is_valid("T22000129") is False
    assert is_valid("T2200012930") is False


def test_none_and_empty():
    assert is_valid(None) is False
    assert is_valid("") is False
