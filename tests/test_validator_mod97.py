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

"""mod-97 validator parity tests (mirrors the Phileas Java Mod97ValidatorTest)."""

import pytest

from phileas.filters.identifier_validators.mod97 import (
    is_valid_nir,
    is_valid_iban,
    DEFAULT_NIR_SUBSTITUTIONS,
)
from phileas.filters.validators import resolve_validator

NIR_SUBS = DEFAULT_NIR_SUBSTITUTIONS


def test_registered():
    assert resolve_validator({"name": "mod97", "params": {"variant": "iban"}})("GB82WEST12345698765432") is True


def test_valid_nir():
    assert is_valid_nir("255081416802538", NIR_SUBS) is True


def test_valid_nir_corsica_2a():
    assert is_valid_nir("220032A00801642", NIR_SUBS) is True


def test_invalid_nir_key():
    assert is_valid_nir("255081416802539", NIR_SUBS) is False


def test_nir_wrong_length():
    assert is_valid_nir("25508141680253", NIR_SUBS) is False


def test_nir_non_numeric_body_without_substitution():
    assert is_valid_nir("2200Q2A00801642", NIR_SUBS) is False


def test_valid_iban_gb():
    assert is_valid_iban("GB82WEST12345698765432") is True


def test_valid_iban_de_with_spaces():
    assert is_valid_iban("DE89 3704 0044 0532 0130 00") is True


def test_invalid_iban():
    assert is_valid_iban("GB82WEST12345698765431") is False


def test_iban_wrong_structure():
    assert is_valid_iban("1234") is False


def test_none_is_invalid():
    assert is_valid_nir(None, NIR_SUBS) is False
    assert is_valid_iban(None) is False


def test_from_params_requires_variant():
    with pytest.raises(ValueError):
        resolve_validator("mod97")


def test_from_params_unknown_variant():
    with pytest.raises(ValueError):
        resolve_validator({"name": "mod97", "params": {"variant": "rib"}})
