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
Applies a Phileas policy to text.

Detection is delegated to the filters; everything else is centralized here and
driven by the PhiSQL catalog. For each built-in entity the catalog resolves the
``identifiers`` field name and the filter-strategies array name, so the engine
never hard-codes those mappings (the catalog even fixes quirks like the
singular ``zipCodeFilterStrategy`` and abbreviated ``bitcoinFilterStrategies``).
Custom identifiers, dictionaries, and ph-eyes are read from the policy in the
PhiSQL compiler's JSON shape.
"""

from __future__ import annotations

import re
from typing import List, Tuple, Type

from phileas.catalog import get_catalog
from phileas.models.filter_result import FilterResult
from phileas.models.span import Span
from phileas.policy.policy import Policy
from phileas.policy.strategy import Strategy
from phileas.filters.base import BaseFilter
from phileas.filters.age_filter import AgeFilter
from phileas.filters.email_address_filter import EmailAddressFilter
from phileas.filters.credit_card_filter import CreditCardFilter
from phileas.filters.ssn_filter import SSNFilter
from phileas.filters.phone_number_filter import PhoneNumberFilter
from phileas.filters.ip_address_filter import IPAddressFilter
from phileas.filters.url_filter import URLFilter
from phileas.filters.zip_code_filter import ZipCodeFilter
from phileas.filters.vin_filter import VINFilter
from phileas.filters.bitcoin_address_filter import BitcoinAddressFilter
from phileas.filters.bank_routing_number_filter import BankRoutingNumberFilter
from phileas.filters.date_filter import DateFilter
from phileas.filters.mac_address_filter import MACAddressFilter
from phileas.filters.currency_filter import CurrencyFilter
from phileas.filters.street_address_filter import StreetAddressFilter
from phileas.filters.tracking_number_filter import TrackingNumberFilter
from phileas.filters.drivers_license_filter import DriversLicenseFilter
from phileas.filters.iban_code_filter import IBANCodeFilter
from phileas.filters.passport_number_filter import PassportNumberFilter
from phileas.filters.ph_eye_filter import PhEyeFilter
from phileas.filters.dictionary_filter import DictionaryFilter
from phileas.filters.pattern_filter import PatternFilter
from phileas.services.context.base import AbstractContextService
from phileas.services.context.in_memory_context_service import InMemoryContextService

# Built-in regex filters, in application order, each paired with the PhiSQL
# catalog entity name it implements. The catalog resolves the policy-JSON field
# names from that name.
_BUILTIN_FILTERS: List[Tuple[Type[BaseFilter], str]] = [
    (AgeFilter, "AGE"),
    (EmailAddressFilter, "EMAIL_ADDRESS"),
    (CreditCardFilter, "CREDIT_CARD"),
    (SSNFilter, "SSN"),
    (PhoneNumberFilter, "PHONE_NUMBER"),
    (IPAddressFilter, "IP_ADDRESS"),
    (URLFilter, "URL"),
    (ZipCodeFilter, "ZIP_CODE"),
    (VINFilter, "VIN"),
    (BitcoinAddressFilter, "BITCOIN_ADDRESS"),
    (BankRoutingNumberFilter, "BANK_ROUTING_NUMBER"),
    (DateFilter, "DATE"),
    (MACAddressFilter, "MAC_ADDRESS"),
    (CurrencyFilter, "CURRENCY"),
    (StreetAddressFilter, "STREET_ADDRESS"),
    (TrackingNumberFilter, "TRACKING_NUMBER"),
    (DriversLicenseFilter, "DRIVERS_LICENSE"),
    (IBANCodeFilter, "IBAN_CODE"),
    (PassportNumberFilter, "PASSPORT_NUMBER"),
]

# Custom (list-valued) filter sections: identifiers field -> (filter class,
# strategies-array field name).
_CUSTOM_SECTIONS: List[Tuple[str, Type[BaseFilter], str]] = [
    ("identifiers", PatternFilter, "identifierFilterStrategies"),
    ("dictionaries", DictionaryFilter, "customFilterStrategies"),
    ("pheyes", PhEyeFilter, "phEyeFilterStrategies"),
]


class FilterService:
    def __init__(self, context_service: AbstractContextService | None = None) -> None:
        self._context_service = (
            context_service if context_service is not None else InMemoryContextService()
        )
        self._catalog = get_catalog()

    def filter(self, policy: Policy, context: str, document_id: str, text: str) -> FilterResult:
        """Apply the policy to *text* and return a :class:`FilterResult`."""
        identifiers = policy.identifiers or {}
        spans: List[Span] = []

        # Built-in entity filters (catalog-driven field resolution).
        for filter_cls, entity_name in _BUILTIN_FILTERS:
            entity = self._catalog.get_entity(entity_name)
            if entity is None:
                continue
            node = identifiers.get(entity.phileas_field)
            if not isinstance(node, dict) or node.get("enabled", True) is False:
                continue
            strategies = self._strategies(node.get(entity.phileas_strategies_field, []))
            detected = filter_cls(node).detect(text, context)
            spans.extend(self._apply_strategies(detected, strategies, node, context))

        # Custom identifiers, dictionaries, and ph-eyes (list-valued sections).
        for field, filter_cls, strategies_field in _CUSTOM_SECTIONS:
            for node in identifiers.get(field, []) or []:
                if not isinstance(node, dict) or node.get("enabled", True) is False:
                    continue
                strategies = self._strategies(node.get(strategies_field, []))
                detected = filter_cls(node).detect(text, context)
                spans.extend(self._apply_strategies(detected, strategies, node, context))

        # Policy-level allowlists: mark (but keep) matching spans as ignored.
        policy_ignored = set(policy.ignored)
        policy_ignored_patterns = [re.compile(p) for p in policy.ignored_patterns]
        for span in spans:
            if span.text in policy_ignored:
                span.ignored = True
                continue
            for pattern in policy_ignored_patterns:
                if pattern.fullmatch(span.text):
                    span.ignored = True
                    break

        spans = Span.drop_overlapping_spans(spans)

        filtered_text = self._apply_replacements(text, spans, context)
        return FilterResult(
            context=context,
            document_id=document_id,
            filtered_text=filtered_text,
            spans=spans,
        )

    @staticmethod
    def _strategies(raw) -> List[Strategy]:
        return [Strategy.from_dict(s) for s in (raw or []) if isinstance(s, dict)]

    def _apply_strategies(
        self,
        detected: List[Span],
        strategies: List[Strategy],
        node: dict,
        context: str,
    ) -> List[Span]:
        """Set each span's replacement from the first applicable strategy.

        Spans matching a per-filter ignored term/pattern are dropped. When
        strategies are configured but none of their conditions hold for a span,
        the span is dropped; when no strategies are configured, a default
        REDACT applies.
        """
        node_ignored = set(node.get("ignored", []) or [])
        node_ignored_patterns = [
            re.compile(p["pattern"])
            for p in (node.get("ignoredPatterns", []) or [])
            if isinstance(p, dict) and p.get("pattern")
        ]

        result: List[Span] = []
        for span in detected:
            token = span.text
            if token in node_ignored or any(p.fullmatch(token) for p in node_ignored_patterns):
                continue

            matched = None
            for strategy in strategies:
                if strategy.evaluate_condition(token, context, span.confidence):
                    matched = strategy
                    break
            if strategies and matched is None:
                continue
            if matched is None:
                matched = Strategy.default()

            span.replacement = matched.get_replacement(span.filter_type, token)
            result.append(span)
        return result

    def _apply_replacements(self, text: str, spans: List[Span], context: str) -> str:
        """Rewrite *text* in reverse order, enforcing referential integrity.

        The same token always receives the same replacement within a context.
        """
        filtered_text = text
        for span in sorted(spans, key=lambda s: s.character_start, reverse=True):
            if span.ignored:
                continue
            cached = self._context_service.get(context, span.text)
            if cached is not None:
                span.replacement = cached
            else:
                self._context_service.put(context, span.text, span.replacement)
            filtered_text = (
                filtered_text[: span.character_start]
                + span.replacement
                + filtered_text[span.character_end :]
            )
        return filtered_text
