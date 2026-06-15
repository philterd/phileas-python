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

"""mod-11 validator parity tests (mirrors the Phileas Java Mod11ValidatorTest)."""

import pytest

from phileas.filters.identifier_validators.mod11 import is_valid_cpf, is_valid_cnpj
from phileas.filters.validators import resolve_validator


def test_registered_cpf():
    assert resolve_validator({"name": "mod11", "params": {"variant": "cpf"}})("52998224725") is True


def test_valid_cpf():
    assert is_valid_cpf("52998224725") is True


def test_valid_cpf_formatted():
    assert is_valid_cpf("529.982.247-25") is True


def test_invalid_cpf_check_digit():
    assert is_valid_cpf("52998224724") is False


def test_cpf_all_same_digits_rejected():
    assert is_valid_cpf("11111111111") is False


def test_cpf_wrong_length():
    assert is_valid_cpf("5299822472") is False


def test_valid_cnpj():
    assert is_valid_cnpj("11222333000181") is True


def test_valid_cnpj_formatted():
    assert is_valid_cnpj("11.222.333/0001-81") is True


def test_invalid_cnpj_check_digit():
    assert is_valid_cnpj("11222333000182") is False


def test_cnpj_all_same_digits_rejected():
    assert is_valid_cnpj("00000000000000") is False


def test_from_params_requires_variant():
    with pytest.raises(ValueError):
        resolve_validator("mod11")
    with pytest.raises(ValueError):
        resolve_validator({"name": "mod11"})


def test_from_params_unknown_variant():
    with pytest.raises(ValueError):
        resolve_validator({"name": "mod11", "params": {"variant": "rut"}})
