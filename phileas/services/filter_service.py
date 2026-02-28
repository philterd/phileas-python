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
from typing import List, Tuple, Type

from phileas.models.filter_result import FilterResult
from phileas.models.span import Span
from phileas.policy.policy import Policy
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

# Maps (identifier_attribute_name, filter_class) pairs in order of application.
_FILTER_MAP: List[Tuple[str, Type[BaseFilter]]] = [
    ("age", AgeFilter),
    ("email_address", EmailAddressFilter),
    ("credit_card", CreditCardFilter),
    ("ssn", SSNFilter),
    ("phone_number", PhoneNumberFilter),
    ("ip_address", IPAddressFilter),
    ("url", URLFilter),
    ("zip_code", ZipCodeFilter),
    ("vin", VINFilter),
    ("bitcoin_address", BitcoinAddressFilter),
    ("bank_routing_number", BankRoutingNumberFilter),
    ("date", DateFilter),
    ("mac_address", MACAddressFilter),
    ("currency", CurrencyFilter),
    ("street_address", StreetAddressFilter),
    ("tracking_number", TrackingNumberFilter),
    ("drivers_license", DriversLicenseFilter),
    ("iban_code", IBANCodeFilter),
    ("passport_number", PassportNumberFilter),
]


class FilterService:
    def __init__(self, context_service: AbstractContextService | None = None) -> None:
        self._context_service = context_service if context_service is not None else InMemoryContextService()

    def filter(self, policy: Policy, context: str, document_id: str, text: str) -> FilterResult:
        """Apply the policy filters to the text and return a FilterResult."""
        spans: List[Span] = []
        identifiers = policy.identifiers

        # Build and apply each enabled filter
        for attr, filter_cls in _FILTER_MAP:
            config = getattr(identifiers, attr, None)
            if config is not None and getattr(config, "enabled", True):
                spans.extend(filter_cls(config).filter(text, context))

        # Apply each ph-eye filter in the list
        for ph_eye_config in identifiers.ph_eye:
            if ph_eye_config.enabled:
                spans.extend(PhEyeFilter(ph_eye_config).filter(text, context))

        # Apply each dictionary filter in the list
        for dict_config in identifiers.dictionaries:
            if dict_config.enabled:
                spans.extend(DictionaryFilter(dict_config).filter(text, context))

        # Apply each pattern filter in the list
        for pattern_config in identifiers.patterns:
            if pattern_config.enabled:
                spans.extend(PatternFilter(pattern_config).filter(text, context))

        # Mark spans whose text matches a policy-level ignored term or pattern
        policy_ignored = set(policy.ignored)
        policy_ignored_patterns = [re.compile(p) for p in policy.ignored_patterns]
        for span in spans:
            if span.text in policy_ignored:
                span.ignored = True
                continue
            for pat in policy_ignored_patterns:
                if pat.fullmatch(span.text):
                    span.ignored = True
                    break

        # Remove overlapping spans
        spans = Span.drop_overlapping_spans(spans)

        # Apply replacements in reverse order to maintain indices.
        # Use the context service to ensure referential integrity: the same token
        # always receives the same replacement within a given context.
        filtered_text = text
        for span in sorted(spans, key=lambda s: s.character_start, reverse=True):
            if not span.ignored:
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

        return FilterResult(
            context=context,
            document_id=document_id,
            filtered_text=filtered_text,
            spans=spans,
        )

