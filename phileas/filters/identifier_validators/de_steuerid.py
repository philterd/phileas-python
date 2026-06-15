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
"""German Steuer-ID (tax ID) validator (parity port of Phileas Java).

Applies the structural digit-repetition rule on the first ten digits and the
ISO/IEC 7064 MOD 11,10 check digit.
"""

from __future__ import annotations

import re

from ..validators import register_validator


def is_valid(text: str) -> bool:
    if text is None:
        return False

    digits = re.sub(r"[\s./-]", "", text)
    if not (len(digits) == 11 and all("0" <= c <= "9" for c in digits)):
        return False

    if digits[0] == "0":
        return False

    if not _has_valid_repetition(digits[:10]):
        return False

    return _check_digit(digits[:10]) == (ord(digits[10]) - 48)


def _has_valid_repetition(first_ten: str) -> bool:
    counts = [0] * 10
    for c in first_ten:
        counts[ord(c) - 48] += 1

    twice = sum(1 for c in counts if c == 2)
    thrice = sum(1 for c in counts if c == 3)

    if any(c > 3 for c in counts):
        return False

    return (twice == 1 and thrice == 0) or (twice == 0 and thrice == 1)


def _check_digit(first_ten: str) -> int:
    product = 10
    for c in first_ten:
        s = (ord(c) - 48 + product) % 10
        if s == 0:
            s = 10
        product = (s * 2) % 11
    return (11 - product) % 10


register_validator("de-steuerid", lambda params: is_valid)
