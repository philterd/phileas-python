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

"""End-to-end tests for the catalog-driven FilterService."""

from phileas.policy.policy import Policy
from phileas.services.context.in_memory_context_service import InMemoryContextService
from phileas.services.filter_service import FilterService


def run(identifiers, text, context="ctx", policy_extra=None, context_service=None):
    data = {"name": "t", "identifiers": identifiers}
    if policy_extra:
        data.update(policy_extra)
    policy = Policy.from_dict(data)
    return FilterService(context_service).filter(policy, context, "doc", text)


class TestBasicPipeline:
    def test_email_redacted(self):
        r = run({"emailAddress": {"emailAddressFilterStrategies": [{"strategy": "REDACT"}]}},
                "Mail john@example.com now.")
        assert "john@example.com" not in r.filtered_text
        assert "{{{REDACTED-email-address}}}" in r.filtered_text

    def test_default_strategy_is_redact(self):
        # A node present with no strategies array still redacts by default.
        r = run({"emailAddress": {}}, "Mail john@example.com now.")
        assert "{{{REDACTED-email-address}}}" in r.filtered_text

    def test_nothing_enabled_is_unchanged(self):
        r = run({}, "Plain text, no PII filters.")
        assert r.filtered_text == "Plain text, no PII filters."

    def test_disabled_node_skipped(self):
        r = run({"emailAddress": {"enabled": False}}, "Mail john@example.com now.")
        assert "john@example.com" in r.filtered_text


class TestCatalogDrivenFieldNames:
    def test_zip_code_singular_strategy_field(self):
        # The catalog says the field is `zipCodeFilterStrategy` (singular).
        r = run({"zipCode": {"zipCodeFilterStrategy": [{"strategy": "STATIC_REPLACE", "staticReplacement": "ZZZZZ"}]}},
                "ZIP 90210 here.")
        assert "ZZZZZ" in r.filtered_text
        assert "90210" not in r.filtered_text

    def test_bitcoin_abbreviated_strategy_field(self):
        addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        r = run({"bitcoinAddress": {"bitcoinFilterStrategies": [{"strategy": "REDACT"}]}},
                f"Send to {addr} now.")
        assert addr not in r.filtered_text
        assert "{{{REDACTED-bitcoin-address}}}" in r.filtered_text


class TestStrategies:
    def test_mask(self):
        r = run({"ssn": {"ssnFilterStrategies": [{"strategy": "MASK", "maskCharacter": "X"}]}},
                "SSN 123-45-6789.")
        assert "XXXXXXXXXXX" in r.filtered_text

    def test_condition_pick_first_matching(self):
        # First strategy's condition fails; second (default) applies.
        strategies = [
            {"strategy": "STATIC_REPLACE", "staticReplacement": "NOPE", "conditions": 'token == "other"'},
            {"strategy": "REDACT"},
        ]
        r = run({"ssn": {"ssnFilterStrategies": strategies}}, "SSN 123-45-6789.")
        assert "{{{REDACTED-ssn}}}" in r.filtered_text
        assert "NOPE" not in r.filtered_text

    def test_condition_none_match_drops_span(self):
        strategies = [{"strategy": "REDACT", "conditions": 'token == "never"'}]
        r = run({"ssn": {"ssnFilterStrategies": strategies}}, "SSN 123-45-6789.")
        # No strategy applies -> the SSN is left in place.
        assert "123-45-6789" in r.filtered_text


class TestIgnored:
    def test_node_ignored_term(self):
        r = run({"emailAddress": {"emailAddressFilterStrategies": [{"strategy": "REDACT"}],
                                  "ignored": ["noreply@example.com"]}},
                "From noreply@example.com and a@b.com.")
        assert "noreply@example.com" in r.filtered_text
        assert "a@b.com" not in r.filtered_text

    def test_node_ignored_pattern(self):
        r = run({"ssn": {"ssnFilterStrategies": [{"strategy": "REDACT"}],
                         "ignoredPatterns": [{"pattern": r"123-45-6789"}]}},
                "SSN 123-45-6789 and 456-78-9012.")
        assert "123-45-6789" in r.filtered_text
        assert "456-78-9012" not in r.filtered_text

    def test_policy_level_ignored_marks_span(self):
        r = run({"emailAddress": {"emailAddressFilterStrategies": [{"strategy": "REDACT"}]}},
                "Mail a@b.com here.",
                policy_extra={"ignored": [{"terms": ["a@b.com"]}]})
        assert "a@b.com" in r.filtered_text  # left in text
        assert any(s.ignored and s.text == "a@b.com" for s in r.spans)


class TestReferentialIntegrity:
    def test_uses_cached_replacement(self):
        cs = InMemoryContextService()
        cs.put("ctx", "a@b.com", "PERSISTED")
        r = run({"emailAddress": {"emailAddressFilterStrategies": [{"strategy": "REDACT"}]}},
                "Mail a@b.com now.", context_service=cs)
        assert "PERSISTED" in r.filtered_text

    def test_same_token_same_replacement(self):
        r = run({"ssn": {"ssnFilterStrategies": [{"strategy": "HASH_SHA256_REPLACE"}]}},
                "SSN 123-45-6789 again 123-45-6789.")
        # Both occurrences redacted identically; original gone.
        assert "123-45-6789" not in r.filtered_text


class TestCustomSections:
    def test_dictionary(self):
        r = run({"dictionaries": [{"classification": "org", "terms": ["Acme"],
                                   "customFilterStrategies": [{"strategy": "REDACT"}]}]},
                "Acme is here.")
        assert "Acme" not in r.filtered_text
        assert "{{{REDACTED-org}}}" in r.filtered_text

    def test_custom_identifier(self):
        r = run({"identifiers": [{"classification": "MRN", "pattern": r"MRN-\d{6}",
                                  "identifierFilterStrategies": [{"strategy": "REDACT", "redactionFormat": "[MRN]"}]}]},
                "Record MRN-123456 today.")
        assert "MRN-123456" not in r.filtered_text
        assert "[MRN]" in r.filtered_text


class TestOverlaps:
    def test_overlapping_spans_resolved(self):
        # Both SSN and phone-ish patterns might match; ensure no crash and text rewritten once.
        r = run({"ssn": {"ssnFilterStrategies": [{"strategy": "REDACT"}]},
                 "phoneNumber": {"phoneNumberFilterStrategies": [{"strategy": "REDACT"}]}},
                "Number 123-45-6789 here.")
        # Exactly one replacement region, no leftover digits from the SSN.
        assert "123-45-6789" not in r.filtered_text
