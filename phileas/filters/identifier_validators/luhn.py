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
"""Standard mod-10 Luhn checksum validator (parity port of Phileas Java)."""

from __future__ import annotations

from ..validators import register_validator


def is_valid(text: str) -> bool:
    """Run the mod-10 Luhn checksum over the digits of ``text``.

    Non-digit characters are ignored, so formatted and unformatted values are
    treated the same.
    """
    if text is None:
        return False

    total = 0
    double = False
    digit_count = 0

    for c in reversed(text):
        if not ("0" <= c <= "9"):
            continue
        d = ord(c) - ord("0")
        digit_count += 1
        if double:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        double = not double

    return digit_count > 0 and total % 10 == 0


register_validator("luhn", lambda params: is_valid)
