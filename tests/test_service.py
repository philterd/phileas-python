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

"""Tests for the FilterService pipeline."""

import pytest

from phileas.policy.policy import Policy
from phileas.policy.filter_strategy import FilterStrategy
from phileas.policy.identifiers import (
    EmailAddressFilterConfig,
    SSNFilterConfig,
    AgeFilterConfig,
    PhoneNumberFilterConfig,
    IPAddressFilterConfig,
    CreditCardFilterConfig,
    URLFilterConfig,
    DateFilterConfig,
    MACAddressFilterConfig,
    CurrencyFilterConfig,
)
from phileas.services.filter_service import FilterService


def _service():
    return FilterService()


def _policy_with(**kwargs):
    """Build a policy with the given identifiers enabled."""
    p = Policy(name="test")
    ids = p.identifiers
    for key, val in kwargs.items():
        setattr(ids, key, val)
    return p


# ---------------------------------------------------------------------------
# Basic pipeline tests
# ---------------------------------------------------------------------------

class TestFilterServiceBasic:
    def test_email_redacted(self):
        policy = _policy_with(email_address=EmailAddressFilterConfig())
        svc = _service()
        result = svc.filter(policy, "ctx", "doc1", "Email john@example.com here.")
        assert "john@example.com" not in result.filtered_text
        assert "{{{REDACTED-email-address}}}" in result.filtered_text
        assert len(result.spans) == 1

    def test_ssn_redacted(self):
        policy = _policy_with(ssn=SSNFilterConfig())
        svc = _service()
        result = svc.filter(policy, "ctx", "doc2", "SSN: 123-45-6789.")
        assert "123-45-6789" not in result.filtered_text
        assert len(result.spans) >= 1

    def test_age_redacted(self):
        policy = _policy_with(age=AgeFilterConfig())
        svc = _service()
        result = svc.filter(policy, "ctx", "doc3", "Patient is 45 years old.")
        assert "45 years old" not in result.filtered_text

    def test_no_filters_enabled_unchanged(self):
        policy = Policy(name="empty")
        svc = _service()
        text = "Nothing to filter here."
        result = svc.filter(policy, "ctx", "doc4", text)
        assert result.filtered_text == text
        assert len(result.spans) == 0

    def test_multiple_filters(self):
        policy = _policy_with(
            email_address=EmailAddressFilterConfig(),
            ssn=SSNFilterConfig(),
        )
        svc = _service()
        text = "Email: a@b.com SSN: 123-45-6789"
        result = svc.filter(policy, "ctx", "doc5", text)
        assert "a@b.com" not in result.filtered_text
        assert "123-45-6789" not in result.filtered_text
        assert len(result.spans) >= 2

    def test_filter_result_fields(self):
        policy = _policy_with(email_address=EmailAddressFilterConfig())
        svc = _service()
        result = svc.filter(policy, "myctx", "mydoc", "test@example.com")
        assert result.context == "myctx"
        assert result.document_id == "mydoc"


# ---------------------------------------------------------------------------
# Strategy tests via service
# ---------------------------------------------------------------------------

class TestFilterServiceStrategies:
    def test_mask_strategy(self):
        config = EmailAddressFilterConfig(
            email_address_filter_strategies=[FilterStrategy(strategy="MASK")]
        )
        policy = _policy_with(email_address=config)
        svc = _service()
        result = svc.filter(policy, "ctx", "doc", "Email: test@example.com")
        assert "*" * len("test@example.com") in result.filtered_text

    def test_static_replace_strategy(self):
        config = SSNFilterConfig(
            ssn_filter_strategies=[
                FilterStrategy(strategy="STATIC_REPLACE", static_replacement="XXX-XX-XXXX")
            ]
        )
        policy = _policy_with(ssn=config)
        svc = _service()
        result = svc.filter(policy, "ctx", "doc", "My SSN is 123-45-6789.")
        assert "XXX-XX-XXXX" in result.filtered_text

    def test_hash_strategy(self):
        import hashlib
        token = "test@example.com"
        config = EmailAddressFilterConfig(
            email_address_filter_strategies=[FilterStrategy(strategy="HASH_SHA256_REPLACE")]
        )
        policy = _policy_with(email_address=config)
        svc = _service()
        result = svc.filter(policy, "ctx", "doc", f"Email: {token}")
        expected = hashlib.sha256(token.encode()).hexdigest()
        assert expected in result.filtered_text

    def test_same_strategy(self):
        config = EmailAddressFilterConfig(
            email_address_filter_strategies=[FilterStrategy(strategy="SAME")]
        )
        policy = _policy_with(email_address=config)
        svc = _service()
        result = svc.filter(policy, "ctx", "doc", "Email: user@example.com")
        assert "user@example.com" in result.filtered_text


# ---------------------------------------------------------------------------
# Policy-level ignored terms
# ---------------------------------------------------------------------------

class TestFilterServiceIgnored:
    def test_policy_ignored_term_not_replaced(self):
        policy = _policy_with(email_address=EmailAddressFilterConfig())
        policy.ignored = ["noreply@example.com"]
        svc = _service()
        result = svc.filter(policy, "ctx", "doc", "Email: noreply@example.com")
        assert "noreply@example.com" in result.filtered_text

    def test_policy_ignored_pattern_not_replaced(self):
        policy = _policy_with(email_address=EmailAddressFilterConfig())
        policy.ignored_patterns = [r"noreply@.*"]
        svc = _service()
        result = svc.filter(policy, "ctx", "doc", "Email: noreply@example.com")
        assert "noreply@example.com" in result.filtered_text

    def test_non_ignored_email_still_replaced(self):
        policy = _policy_with(email_address=EmailAddressFilterConfig())
        policy.ignored = ["noreply@example.com"]
        svc = _service()
        result = svc.filter(policy, "ctx", "doc", "Email user@example.com")
        assert "user@example.com" not in result.filtered_text


# ---------------------------------------------------------------------------
# Overlapping spans
# ---------------------------------------------------------------------------

class TestOverlappingSpans:
    def test_overlapping_resolved(self):
        """SSN unformatted may overlap with phone; only one should survive."""
        from phileas.models.span import Span
        spans = [
            Span(0, 10, "ssn", "ctx", 1.0, "1234567890", "{{{REDACTED-ssn}}}"),
            Span(5, 15, "phone-number", "ctx", 0.8, "1234567890", "{{{REDACTED-phone-number}}}"),
        ]
        result = Span.drop_overlapping_spans(spans)
        assert len(result) == 1
        assert result[0].filter_type == "ssn"  # higher confidence wins

    def test_non_overlapping_both_kept(self):
        from phileas.models.span import Span
        spans = [
            Span(0, 5, "ssn", "ctx", 1.0, "hello", "{{{REDACTED-ssn}}}"),
            Span(10, 15, "email-address", "ctx", 1.0, "world", "{{{REDACTED-email-address}}}"),
        ]
        result = Span.drop_overlapping_spans(spans)
        assert len(result) == 2


# ---------------------------------------------------------------------------
# From-JSON policy integration
# ---------------------------------------------------------------------------

class TestFilterServiceFromJSON:
    def test_json_policy_email_redact(self):
        import json
        policy_json = json.dumps({
            "name": "default",
            "identifiers": {
                "emailAddress": {
                    "emailAddressFilterStrategies": [{"strategy": "REDACT", "redactionFormat": "{{{REDACTED-%t}}}"}]
                }
            },
            "ignored": [],
        })
        policy = Policy.from_json(policy_json)
        svc = _service()
        result = svc.filter(policy, "ctx", "doc", "Contact admin@company.org for help.")
        assert "admin@company.org" not in result.filtered_text
        assert "{{{REDACTED-email-address}}}" in result.filtered_text

    def test_json_policy_disabled_filter(self):
        import json
        policy_json = json.dumps({
            "name": "default",
            "identifiers": {
                "emailAddress": {"enabled": False}
            },
        })
        policy = Policy.from_json(policy_json)
        svc = _service()
        result = svc.filter(policy, "ctx", "doc", "Email: test@example.com")
        assert "test@example.com" in result.filtered_text

    def test_multiple_pii_types_redacted(self):
        import json
        policy_json = json.dumps({
            "name": "default",
            "identifiers": {
                "emailAddress": {},
                "phoneNumber": {},
                "ipAddress": {},
            },
        })
        policy = Policy.from_json(policy_json)
        svc = _service()
        text = "Email test@x.com, call 800-555-1234, IP 10.0.0.1."
        result = svc.filter(policy, "ctx", "doc", text)
        assert "test@x.com" not in result.filtered_text
        assert "10.0.0.1" not in result.filtered_text


# ---------------------------------------------------------------------------
# ContextService injection
# ---------------------------------------------------------------------------

class TestFilterServiceContextService:
    def test_default_context_service_is_in_memory(self):
        from phileas.services.context import InMemoryContextService
        svc = FilterService()
        assert isinstance(svc._context_service, InMemoryContextService)

    def test_custom_context_service_is_used(self):
        from phileas.services.context import AbstractContextService, InMemoryContextService

        class CustomContextService(AbstractContextService):
            def put(self, context, token, replacement): pass
            def get(self, context, token): return None
            def contains(self, context, token): return False

        custom = CustomContextService()
        svc = FilterService(context_service=custom)
        assert svc._context_service is custom

    def test_filter_with_custom_context_service(self):
        from phileas.services.context import InMemoryContextService
        ctx_svc = InMemoryContextService()
        svc = FilterService(context_service=ctx_svc)
        policy = _policy_with(email_address=EmailAddressFilterConfig())
        result = svc.filter(policy, "ctx", "doc", "Email: user@example.com")
        assert "user@example.com" not in result.filtered_text

    def test_context_referential_integrity_reuses_replacement(self):
        """The same token in the same context must always get the same replacement."""
        from phileas.services.context import InMemoryContextService
        ctx_svc = InMemoryContextService()
        svc = FilterService(context_service=ctx_svc)
        policy = _policy_with(email_address=EmailAddressFilterConfig())

        result1 = svc.filter(policy, "ctx", "doc1", "Contact user@example.com for info.")
        result2 = svc.filter(policy, "ctx", "doc2", "Reply to user@example.com today.")

        # The replacement strings for the same token must be identical across calls
        replacement1 = result1.spans[0].replacement
        replacement2 = result2.spans[0].replacement
        assert replacement1 == replacement2

    def test_context_referential_integrity_pre_seeded(self):
        """A token pre-seeded in the context service is used as the replacement."""
        from phileas.services.context import InMemoryContextService
        ctx_svc = InMemoryContextService()
        ctx_svc.put("ctx", "user@example.com", "KNOWN-REPLACEMENT")
        svc = FilterService(context_service=ctx_svc)
        policy = _policy_with(email_address=EmailAddressFilterConfig())

        result = svc.filter(policy, "ctx", "doc1", "Email: user@example.com here.")
        assert "KNOWN-REPLACEMENT" in result.filtered_text
        assert result.spans[0].replacement == "KNOWN-REPLACEMENT"
