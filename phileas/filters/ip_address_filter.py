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


# Every IPv6 form: expanded, expanded mixed, compressed, IPv4-mapped, and link-local with a zone.
# From Dynatrace's InetAddressValidator (Apache 2.0), which uses it anchored.
_IPV6_ALTERNATIVES = (
    r"(?:"
    r"(?:[\da-f]{1,4}:){7}[\da-f]{1,4}"
    r"|(?:[\da-f]{1,4}:){6}(?:(?:25[0-5]|(?:2[0-4]|1?\d)?\d)\.){3}(?:25[0-5]|(?:2[0-4]|1?\d)?\d)"
    r"|(?:[\da-f]{1,4}:){1,7}:"
    r"|(?:[\da-f]{1,4}:){1,6}:[\da-f]{1,4}"
    r"|(?:[\da-f]{1,4}:){1,5}(?::[\da-f]{1,4}){1,2}"
    r"|(?:[\da-f]{1,4}:){1,4}(?::[\da-f]{1,4}){1,3}"
    r"|(?:[\da-f]{1,4}:){1,3}(?::[\da-f]{1,4}){1,4}"
    r"|(?:[\da-f]{1,4}:){1,2}(?::[\da-f]{1,4}){1,5}"
    r"|[\da-f]{1,4}:(?::[\da-f]{1,4}){1,6}"
    r"|:(?:(?::[\da-f]{1,4}){1,7}|:)"
    r"|fe80:(?::[\da-f]{0,4}){0,4}%[\da-z]+"
    r"|::(?:ffff(?::0{1,4})?:)?(?:(?:25[0-5]|(?:2[0-4]|1?\d)?\d)\.){3}(?:25[0-5]|(?:2[0-4]|1?\d)?\d)"
    r"|(?:[\da-f]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1?\d)?\d)\.){3}(?:25[0-5]|(?:2[0-4]|1?\d)?\d)"
    r")"
)

# Zone identifier, e.g. "fe80::1%eth0", or "%25eth0" percent-encoded for a URI.
_IPV6_ZONE = r"(?:%[\da-z]+)?"

# An address is a whole token, so "std::vector" is not one. A plain \b will not do: it fails in
# front of a leading "::".
_IPV6_LEADING_BOUNDARY = r"(?<!\w)"

# `re` takes the first matching alternative, not the longest, so a compressed address stopped at
# its "::". Rejecting a match that ends mid-address makes the engine backtrack into a full one.
_IPV6_TRAILING_BOUNDARY = r"(?!\w)(?!:[\da-f])(?!\.\d)"


_PATTERNS = [
    # IPv4
    re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    # IPv6, any form, with an optional zone.
    re.compile(
        _IPV6_LEADING_BOUNDARY + _IPV6_ALTERNATIVES + _IPV6_ZONE + _IPV6_TRAILING_BOUNDARY,
        re.IGNORECASE,
    ),
]


class IPAddressFilter(BaseFilter):
    def __init__(self, config=None):
        super().__init__(FilterType.IP_ADDRESS, config)

    def detect(self, text: str, context: str = "default") -> List[Span]:
        # The IPv4 pattern also matches the dotted quad inside an IPv4-mapped address.
        return Span.drop_overlapping_spans(self._detect_patterns(_PATTERNS, text, context))
