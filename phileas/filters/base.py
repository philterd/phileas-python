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
"""
Detection filters.

A filter's sole job is *detection*: scan text and return the spans of sensitive
information it finds. It does not know about strategies, conditions, ignored
terms, or referential integrity — those are applied centrally by
:class:`phileas.services.filter_service.FilterService` using the PhiSQL catalog.
Detected spans carry an empty ``replacement``; the service fills it in.

Each filter is constructed with its policy *config* — the filter node from the
policy ``identifiers`` object (a plain dict). Most regex filters ignore it;
filters like credit card (luhn), dictionary, pattern, and ph-eye read options
from it.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import List, Optional

from phileas.models.span import Span


class FilterType:
    AGE = "age"
    EMAIL_ADDRESS = "email-address"
    CREDIT_CARD = "credit-card"
    SSN = "ssn"
    EIN = "ein"
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
    def __init__(self, filter_type: str, config: Optional[dict] = None) -> None:
        self.filter_type = filter_type
        self.config: dict = config or {}

    @abstractmethod
    def detect(self, text: str, context: str = "default") -> List[Span]:
        """Return the spans of sensitive information found in *text*."""
        ...

    def _detect_patterns(
        self,
        patterns: List[re.Pattern],
        text: str,
        context: str,
        confidence: float = 1.0,
    ) -> List[Span]:
        """Return a span for every match of every pattern (no replacement set)."""
        spans: List[Span] = []
        for pattern in patterns:
            for match in pattern.finditer(text):
                spans.append(
                    Span(
                        character_start=match.start(),
                        character_end=match.end(),
                        filter_type=self.filter_type,
                        context=context,
                        confidence=confidence,
                        text=match.group(0),
                        replacement="",
                        ignored=False,
                    )
                )
        return spans
