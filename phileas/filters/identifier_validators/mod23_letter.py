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
"""Control-letter validator (parity port of Phileas Java).

Validates the Spanish DNI and NIE: the control letter is taken from a 23-entry
table indexed by the number mod 23.
"""

from __future__ import annotations

import re

from ..validators import register_validator

_CONTROL_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"

DEFAULT_PREFIX_SUBSTITUTIONS = {"X": "0", "Y": "1", "Z": "2"}


def is_valid(text: str, prefix_substitutions) -> bool:
    if text is None:
        return False

    s = re.sub(r"[\s-]", "", text.strip().upper())
    if len(s) != 9:
        return False

    control = s[8]
    if not ("A" <= control <= "Z"):
        return False

    prefix = s[0]
    if prefix in prefix_substitutions:
        rest = s[1:8]
        if not (len(rest) == 7 and all("0" <= c <= "9" for c in rest)):
            return False
        number_part = prefix_substitutions[prefix] + rest
    else:
        number_part = s[0:8]
        if not all("0" <= c <= "9" for c in number_part):
            return False

    n = int(number_part)
    return _CONTROL_LETTERS[n % 23] == control


def _factory(params):
    subs = (params or {}).get("substitutions")
    subs = {str(k).upper(): str(v).upper() for k, v in subs.items()} if isinstance(subs, dict) else dict(DEFAULT_PREFIX_SUBSTITUTIONS)
    return lambda text: is_valid(text, subs)


register_validator("mod23-letter", _factory)
