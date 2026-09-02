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


# Every IPv6 form in one alternation: expanded, expanded mixed (six hextets and a dotted quad),
# compressed, IPv4-mapped, and link-local with a zone. Taken from Dynatrace's InetAddressValidator
# (Apache 2.0), which uses it anchored; unanchored it needs the boundaries below.
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

# An optional zone identifier, e.g. "fe80::1%eth0", or "%25eth0" percent-encoded for a URI.
_IPV6_ZONE = r"(?:%[\da-z]+)?"

# An address is a whole token. A plain \b will not do: it fails in front of a leading "::", which is
# why "::1" went undetected before. A word character on either side means the match started or
# stopped inside some longer word, so "std::vector" and "Employee::getName" are not addresses.
_IPV6_LEADING_BOUNDARY = r"(?<!\w)"

# The alternation is ordered and `re` takes the first alternative that matches, not the longest, so
# a compressed address matched only as far as its "::". Together with the leading boundary this
# rejects a match that stopped inside an address, so the engine backtracks into one that consumes
# all of it: not a bare hex digit ("FE80::" out of "FE80::1"), not a further hextet, and not a
# further IPv4 octet. A period not followed by a digit still ends the match, so a trailing sentence
# period is left out rather than blocking the match.
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
        # The IPv4 pattern also matches the dotted quad inside an IPv4-mapped address, so resolve
        # overlaps here rather than leaving two spans for one address.
        return Span.drop_overlapping_spans(self._detect_patterns(_PATTERNS, text, context))
