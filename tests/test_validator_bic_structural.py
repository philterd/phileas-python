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

"""BIC/SWIFT structural parity tests (mirrors the Phileas Java BicStructuralValidatorTest)."""

from phileas.filters.identifier_validators.bic_structural import is_valid
from phileas.filters.validators import resolve_validator


def test_registered():
    assert resolve_validator("bic-structural")("DEUTDEFF") is True


def test_valid_8_char_bic():
    assert is_valid("DEUTDEFF") is True


def test_valid_11_char_bic_with_branch():
    assert is_valid("DEUTDEFF500") is True


def test_valid_bic_united_states():
    assert is_valid("BOFAUS3N") is True


def test_valid_bic_another_country():
    assert is_valid("NEDSZAJJ") is True


def test_case_insensitive():
    assert is_valid("deutdeff") is True


def test_surrounding_whitespace_ignored():
    assert is_valid("  DEUTDEFF  ") is True


def test_invalid_country_code():
    assert is_valid("DEUTZZFF") is False


def test_country_segment_must_be_letters():
    assert is_valid("DEUT12FF") is False


def test_institution_code_must_be_letters():
    assert is_valid("DEU1DEFF") is False


def test_wrong_lengths():
    assert is_valid("DEUTDEF") is False
    assert is_valid("DEUTDEFF5") is False
    assert is_valid("DEUTDEFF50") is False


def test_none_and_empty():
    assert is_valid(None) is False
    assert is_valid("") is False
