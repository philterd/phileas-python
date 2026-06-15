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
"""Spanish CIF control validator (parity port of Phileas Java)."""

from __future__ import annotations

import re

from ..validators import register_validator

_VALID_FIRST = "ABCDEFGHJNPQRSUVW"
_CONTROL_LETTERS = "JABCDEFGHI"


def is_valid(text: str) -> bool:
    if text is None:
        return False

    s = re.sub(r"[\s-]", "", text.strip().upper())
    if len(s) != 9:
        return False

    if s[0] not in _VALID_FIRST:
        return False

    middle = s[1:8]
    if not all("0" <= c <= "9" for c in middle):
        return False

    total = 0
    for i in range(7):
        digit = ord(middle[i]) - 48
        if i % 2 == 0:
            # Odd position (1-based): double and sum the resulting digits.
            doubled = digit * 2
            total += (doubled // 10) + (doubled % 10)
        else:
            total += digit

    check = (10 - (total % 10)) % 10
    control = s[8]

    if "0" <= control <= "9":
        return (ord(control) - 48) == check

    return control == _CONTROL_LETTERS[check]


register_validator("es-cif", lambda params: is_valid)
