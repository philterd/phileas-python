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

from __future__ import annotations

import re
from typing import List

from phileas.models.span import Span
from .base import BaseFilter, FilterType


# The host charset has no ":", so without a port group the match stopped at the port and left the
# rest of the URL, path included, in the document. Digits are required after the colon, so a colon
# that is sentence punctuation rather than a port does not extend the match. The bound matches the
# Java port, which uses "(:[\d]{1,5})?".
_PORT = r"(?::\d{1,5})?"


_PATTERNS = [
    re.compile(
        r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+"
        + _PORT
        + r"(?:/(?:[-\w.~!$&'()*+,;=:@%]|(?:%[\da-fA-F]{2}))*)*(?:\?(?:[-\w.~!$&'()*+,;=:@/?%]|(?:%[\da-fA-F]{2}))*)?(?:#(?:[-\w.~!$&'()*+,;=:@/?%]|(?:%[\da-fA-F]{2}))*)?",
        re.IGNORECASE,
    ),
]


class URLFilter(BaseFilter):
    def __init__(self, config=None):
        super().__init__(FilterType.URL, config)

    def detect(self, text: str, context: str = "default") -> List[Span]:
        return self._detect_patterns(_PATTERNS, text, context)
