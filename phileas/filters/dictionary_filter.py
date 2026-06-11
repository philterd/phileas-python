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

import hashlib
import math
import re
from typing import List, Optional

from phileas.models.span import Span
from .base import BaseFilter, FilterType


class BloomFilter:
    """Simple pure-Python Bloom filter for fast term membership testing.

    Uses double hashing (SHA-256 + MD5) to generate *k* independent bit
    positions for each item.  The filter guarantees *no false negatives*:
    if ``item not in bloom`` then the item was definitely never added.
    False positives are possible but controlled by *error_rate*.
    """

    def __init__(self, capacity: int = 1000, error_rate: float = 0.01):
        n = max(capacity, 1)
        # Optimal number of bits: m = -n * ln(p) / (ln 2)^2
        m = max(1, int(-n * math.log(error_rate) / (math.log(2) ** 2)))
        # Optimal number of hash functions: k = (m/n) * ln 2
        k = max(1, int((m / n) * math.log(2)))
        self._num_bits = m
        self._num_hashes = k
        self._bits = bytearray(math.ceil(m / 8))

    def _positions(self, item: str) -> List[int]:
        encoded = item.encode()
        h1 = int(hashlib.sha256(encoded).hexdigest(), 16)
        h2 = int(hashlib.md5(encoded).hexdigest(), 16)  # noqa: S324 - non-security use
        return [(h1 + i * h2) % self._num_bits for i in range(self._num_hashes)]

    def add(self, item: str) -> None:
        for pos in self._positions(item):
            self._bits[pos >> 3] |= 1 << (pos & 7)

    def __contains__(self, item: object) -> bool:
        if not isinstance(item, str):
            return False
        return all(
            self._bits[pos >> 3] & (1 << (pos & 7))
            for pos in self._positions(item)
        )


class DictionaryFilter(BaseFilter):
    """Detects terms from a user-supplied dictionary.

    Config is a dictionary node from ``identifiers.dictionaries``:
    ``classification`` (the filter type) and ``terms`` (the term list). A
    :class:`BloomFilter` provides fast rejection during scanning; an exact set
    verifies matches.
    """

    def __init__(self, config=None):
        config = config or {}
        filter_type = config.get("classification") or FilterType.DICTIONARY
        super().__init__(filter_type, config)

        terms: List[str] = list(config.get("terms", []) or [])
        self._terms_set = {t.lower() for t in terms}
        self._bloom = BloomFilter(capacity=max(len(terms), 1))
        for term in terms:
            self._bloom.add(term.lower())
        if terms:
            sorted_terms = sorted(terms, key=len, reverse=True)
            self._pattern: Optional[re.Pattern] = re.compile(
                r"(?<!\w)(" + "|".join(re.escape(t) for t in sorted_terms) + r")(?!\w)",
                re.IGNORECASE,
            )
        else:
            self._pattern = None

    def detect(self, text: str, context: str = "default") -> List[Span]:
        if self._pattern is None:
            return []
        spans: List[Span] = []
        for match in self._pattern.finditer(text):
            token = match.group(0)
            if token.lower() not in self._bloom:
                continue
            if token.lower() not in self._terms_set:
                continue
            spans.append(
                Span(
                    character_start=match.start(),
                    character_end=match.end(),
                    filter_type=self.filter_type,
                    context=context,
                    confidence=1.0,
                    text=token,
                    replacement="",
                    ignored=False,
                )
            )
        return spans
