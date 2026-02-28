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
from abc import ABC, abstractmethod
from typing import List

from phileas.models.span import Span


class FilterType:
    AGE = "age"
    EMAIL_ADDRESS = "email-address"
    CREDIT_CARD = "credit-card"
    SSN = "ssn"
    PHONE_NUMBER = "phone-number"
    IP_ADDRESS = "ip-address"
    URL = "url"
    ZIP_CODE = "zip-code"
    VIN = "vin"
    BITCOIN_ADDRESS = "bitcoin-address"
    BANK_ROUTING_NUMBER = "bank-routing-number"
    DATE = "date"
    MAC_ADDRESS = "mac-address"
    CURRENCY = "currency"
    STREET_ADDRESS = "street-address"
    TRACKING_NUMBER = "tracking-number"
    DRIVERS_LICENSE = "drivers-license"
    IBAN_CODE = "iban-code"
    PASSPORT_NUMBER = "passport-number"
    PH_EYE = "ph-eye"
    DICTIONARY = "dictionary"
    PATTERN = "pattern"


class BaseFilter(ABC):
    def __init__(self, filter_type: str, filter_config):
        self.filter_type = filter_type
        self.filter_config = filter_config

    @abstractmethod
    def filter(self, text: str, context: str = "default") -> List[Span]:
        """Find spans of sensitive information in text."""
        ...

    def _get_strategies(self) -> list:
        """Return the list of filter strategies from the config."""
        for attr in vars(self.filter_config):
            if attr.endswith("_strategies"):
                return getattr(self.filter_config, attr)
        return []

    def _get_ignored(self) -> list:
        """Return ignored terms from the config."""
        return getattr(self.filter_config, "ignored", [])

    def _find_spans(
        self,
        patterns: List[re.Pattern],
        text: str,
        context: str,
        confidence: float = 1.0,
    ) -> List[Span]:
        """Find all pattern matches in text and return Span objects."""
        spans: List[Span] = []
        strategies = self._get_strategies()
        ignored = self._get_ignored()

        for pattern in patterns:
            for match in pattern.finditer(text):
                token = match.group(0)
                # Skip ignored terms
                if token in ignored:
                    continue

                # Find the first strategy whose condition is satisfied
                matched_strategy = None
                for s in strategies:
                    if s.evaluate_condition(token, context, confidence):
                        matched_strategy = s
                        break

                # If strategies are configured but none matched, skip this token
                if strategies and matched_strategy is None:
                    continue

                replacement = (
                    matched_strategy.get_replacement(self.filter_type, token)
                    if matched_strategy
                    else token
                )
                span = Span(
                    character_start=match.start(),
                    character_end=match.end(),
                    filter_type=self.filter_type,
                    context=context,
                    confidence=confidence,
                    text=token,
                    replacement=replacement,
                    ignored=False,
                )
                spans.append(span)

        return spans

    def apply_strategy(self, spans: List[Span]) -> List[Span]:
        """Apply the filter strategy to each span (already applied in _find_spans)."""
        return spans
