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
"""German Personalausweis (ID card) number validator (parity port of Phileas Java).

Validates the ICAO 9303 7-3-1 weighted check digit over the 9-character document
number.
"""

from __future__ import annotations

from ..validators import register_validator

_WEIGHTS = (7, 3, 1)


def _char_value(c: str) -> int:
    if "0" <= c <= "9":
        return ord(c) - ord("0")
    if "A" <= c <= "Z":
        return 10 + (ord(c) - ord("A"))
    return -1


def is_valid(text: str) -> bool:
    if text is None:
        return False

    s = text.strip().upper()
    if len(s) != 10:
        return False

    check_char = s[9]
    if not ("0" <= check_char <= "9"):
        return False

    total = 0
    for i in range(9):
        value = _char_value(s[i])
        if value < 0:
            return False
        total += value * _WEIGHTS[i % 3]

    return (total % 10) == (ord(check_char) - ord("0"))


register_validator("de-personalausweis", lambda params: is_valid)
