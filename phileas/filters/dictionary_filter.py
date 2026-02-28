from __future__ import annotations

import hashlib
import math
import re
from typing import List

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
    """Filter that identifies terms from a user-supplied dictionary.

    A :class:`BloomFilter` is used for fast membership testing during
    scanning.  An exact ``set`` provides final verification to eliminate
    any bloom false-positives.
    """

    def __init__(self, filter_config):
        super().__init__(FilterType.DICTIONARY, filter_config)
        terms: List[str] = list(getattr(filter_config, "terms", []))
        self._terms_set: set = {t.lower() for t in terms}
        self._bloom = BloomFilter(capacity=max(len(terms), 1))
        for term in terms:
            self._bloom.add(term.lower())
        # Build a regex that matches any term at a word boundary.
        # Sort longest-first so that longer phrases are preferred over prefixes.
        if terms:
            sorted_terms = sorted(terms, key=len, reverse=True)
            self._pattern: re.Pattern | None = re.compile(
                r"(?<!\w)(" + "|".join(re.escape(t) for t in sorted_terms) + r")(?!\w)",
                re.IGNORECASE,
            )
        else:
            self._pattern = None

    def filter(self, text: str, context: str = "default") -> List[Span]:
        if self._pattern is None:
            return []

        strategies = self._get_strategies()
        ignored = set(self._get_ignored())
        spans: List[Span] = []

        for match in self._pattern.finditer(text):
            token = match.group(0)
            if token in ignored:
                continue
            # Bloom filter: fast rejection of tokens not in the dictionary.
            if token.lower() not in self._bloom:
                continue
            # Exact set: verify (handles any bloom false-positives).
            if token.lower() not in self._terms_set:
                continue

            matched_strategy = None
            for s in strategies:
                if s.evaluate_condition(token, context, 1.0):
                    matched_strategy = s
                    break

            if strategies and matched_strategy is None:
                continue

            replacement = (
                matched_strategy.get_replacement(self.filter_type, token)
                if matched_strategy
                else token
            )
            spans.append(
                Span(
                    character_start=match.start(),
                    character_end=match.end(),
                    filter_type=self.filter_type,
                    context=context,
                    confidence=1.0,
                    text=token,
                    replacement=replacement,
                    ignored=False,
                )
            )

        return spans
