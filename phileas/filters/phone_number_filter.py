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


_PATTERNS = [
    # (NXX) NXX-XXXX
    re.compile(r"\b\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}\b"),
    # NXX-NXX-XXXX
    re.compile(r"\b\d{3}[\-\.]\d{3}[\-\.]\d{4}\b"),
    # +1 NXX NXX XXXX or +1-NXX-NXX-XXXX
    re.compile(r"\+1[\s\-]\(?\d{3}\)?[\s\-]\d{3}[\s\-]\d{4}"),
    # 10-digit no separator
    re.compile(r"\b[2-9]\d{2}[2-9]\d{6}\b"),
]


class PhoneNumberFilter(BaseFilter):
    def __init__(self, filter_config):
        super().__init__(FilterType.PHONE_NUMBER, filter_config)

    def filter(self, text: str, context: str = "default") -> List[Span]:
        return self._find_spans(_PATTERNS, text, context)
