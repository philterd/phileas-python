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
"""Weighted-sum mod-11 check-digit validator (parity port of Phileas Java).

Variants: ``cpf`` (Brazilian CPF) and ``cnpj`` (Brazilian CNPJ).
"""

from __future__ import annotations

from ..validators import register_validator


def _digits_only(text: str) -> str:
    return "".join(c for c in text if "0" <= c <= "9") if text else ""


def _all_same(d: str) -> bool:
    return all(c == d[0] for c in d)


def _check(d: str, length: int, start_weight: int) -> int:
    total = sum((ord(d[i]) - 48) * (start_weight - i) for i in range(length))
    remainder = total % 11
    return 0 if remainder < 2 else 11 - remainder


def _check_weights(d: str, weights, length: int) -> int:
    total = sum((ord(d[i]) - 48) * weights[i] for i in range(length))
    remainder = total % 11
    return 0 if remainder < 2 else 11 - remainder


def is_valid_cpf(text: str) -> bool:
    d = _digits_only(text)
    if len(d) != 11 or _all_same(d):
        return False
    c1 = _check(d, 9, 10)
    c2 = _check(d, 10, 11)
    return c1 == (ord(d[9]) - 48) and c2 == (ord(d[10]) - 48)


def is_valid_cnpj(text: str) -> bool:
    d = _digits_only(text)
    if len(d) != 14 or _all_same(d):
        return False
    weights1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    weights2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    c1 = _check_weights(d, weights1, 12)
    c2 = _check_weights(d, weights2, 13)
    return c1 == (ord(d[12]) - 48) and c2 == (ord(d[13]) - 48)


def _factory(params):
    variant = (params or {}).get("variant")
    if variant is None:
        raise ValueError("The mod11 validator requires a 'variant' parameter (cpf or cnpj).")
    v = str(variant).lower()
    if v == "cpf":
        return is_valid_cpf
    if v == "cnpj":
        return is_valid_cnpj
    raise ValueError(f"Unsupported mod11 variant '{variant}'. Supported: cpf, cnpj.")


register_validator("mod11", _factory)
