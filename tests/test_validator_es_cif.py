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

"""Spanish CIF parity tests (mirrors the Phileas Java EsCifValidatorTest)."""

from phileas.filters.identifier_validators.es_cif import is_valid
from phileas.filters.validators import resolve_validator


def test_registered():
    assert resolve_validator("es-cif")("A58818501") is True


def test_valid_cif_digit_control():
    assert is_valid("A58818501") is True


def test_valid_cif_letter_control():
    assert is_valid("P1234567D") is True


def test_case_insensitive():
    assert is_valid("p1234567d") is True


def test_invalid_digit_control():
    assert is_valid("A58818502") is False


def test_invalid_letter_control():
    assert is_valid("P1234567E") is False


def test_invalid_organization_type_letter():
    assert is_valid("I58818501") is False


def test_middle_must_be_digits():
    assert is_valid("A5881X501") is False


def test_wrong_length():
    assert is_valid("A5881850") is False


def test_none_and_empty():
    assert is_valid(None) is False
    assert is_valid("") is False
