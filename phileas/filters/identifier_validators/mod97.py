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
"""Control-key validator based on a value mod 97 (parity port of Phileas Java).

Variants: ``nir`` (French INSEE/NIR) and ``iban``.
"""

from __future__ import annotations

import re

from ..validators import register_validator

DEFAULT_NIR_SUBSTITUTIONS = {"2A": "19", "2B": "18"}

_IBAN_RE = re.compile(r"[A-Z]{2}[0-9]{2}[A-Z0-9]+")


def _is_ascii_digits(s: str) -> bool:
    return len(s) > 0 and all("0" <= c <= "9" for c in s)


def is_valid_nir(text: str, substitutions) -> bool:
    if text is None:
        return False

    s = re.sub(r"\s", "", text).upper()
    if len(s) != 15:
        return False

    body = s[:13]
    key = s[13:]
    if not (len(key) == 2 and _is_ascii_digits(key)):
        return False

    for k, v in substitutions.items():
        body = body.replace(k, v)

    if not (len(body) == 13 and _is_ascii_digits(body)):
        return False

    n = int(body)
    expected_key = 97 - (n % 97)
    return expected_key == int(key)


def is_valid_iban(text: str) -> bool:
    if text is None:
        return False

    s = re.sub(r"\s", "", text).upper()
    if not _IBAN_RE.fullmatch(s) or len(s) < 5 or len(s) > 34:
        return False

    rearranged = s[4:] + s[:4]
    numeric = []
    for c in rearranged:
        if "0" <= c <= "9":
            numeric.append(c)
        else:
            # A-Z map to 10-35.
            numeric.append(str(10 + (ord(c) - ord("A"))))

    return int("".join(numeric)) % 97 == 1


def _normalize_subs(subs):
    return {str(k).upper(): str(v).upper() for k, v in subs.items()}


def _factory(params):
    variant = (params or {}).get("variant")
    if variant is None:
        raise ValueError("The mod97 validator requires a 'variant' parameter (nir or iban).")
    v = str(variant).lower()
    if v == "nir":
        subs = (params or {}).get("substitutions")
        subs = _normalize_subs(subs) if isinstance(subs, dict) else dict(DEFAULT_NIR_SUBSTITUTIONS)
        return lambda text: is_valid_nir(text, subs)
    if v == "iban":
        return is_valid_iban
    raise ValueError(f"Unsupported mod97 variant '{variant}'. Supported: nir, iban.")


register_validator("mod97", _factory)
