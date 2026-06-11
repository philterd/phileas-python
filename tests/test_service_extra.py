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

"""Deeper end-to-end characterization tests for the FilterService pipeline.

These exercise overlap resolution, referential integrity, node- and policy-level
allowlists, strategy selection / conditions, and combined custom sections. All
assertions characterize the *actual* behavior of the reference engine.
"""

import hashlib

import pytest

from phileas.models.span import Span
from phileas.policy.policy import Policy
from phileas.services.context.in_memory_context_service import InMemoryContextService
from phileas.services.filter_service import FilterService


def run(identifiers, text, context="ctx", policy_extra=None, context_service=None):
    data = {"name": "t", "identifiers": identifiers}
    if policy_extra:
        data.update(policy_extra)
    policy = Policy.from_dict(data)
    return FilterService(context_service).filter(policy, context, "doc", text)


def _mk_span(start, end, confidence, filter_type="x", text="tok"):
    return Span(start, end, filter_type, "ctx", confidence, text, "", False)


# --------------------------------------------------------------------------
# Overlap resolution (Span.drop_overlapping_spans is the engine's resolver).
# --------------------------------------------------------------------------
class TestOverlapResolution:
    def test_same_start_higher_confidence_wins(self):
        low = _mk_span(0, 5, 0.5, "low")
        high = _mk_span(0, 8, 0.9, "high")
        kept = Span.drop_overlapping_spans([low, high])
        assert len(kept) == 1
        assert kept[0].filter_type == "high"
        assert kept[0].confidence == 0.9

    def test_same_start_higher_confidence_wins_order_independent(self):
        low = _mk_span(0, 5, 0.5, "low")
        high = _mk_span(0, 8, 0.9, "high")
        kept = Span.drop_overlapping_spans([high, low])
        assert len(kept) == 1
        assert kept[0].filter_type == "high"

    def test_higher_confidence_wins_when_it_starts_later(self):
        # Regression: the higher-confidence span must win even when it starts
        # *after* the lower-confidence span it overlaps.
        low = _mk_span(0, 5, 0.5, "low")
        high = _mk_span(2, 8, 0.9, "high")
        kept = Span.drop_overlapping_spans([low, high])
        assert len(kept) == 1
        assert kept[0].filter_type == "high"

    def test_higher_confidence_wins_when_it_starts_later_order_independent(self):
        low = _mk_span(0, 5, 0.5, "low")
        high = _mk_span(2, 8, 0.9, "high")
        kept = Span.drop_overlapping_spans([high, low])
        assert len(kept) == 1
        assert kept[0].filter_type == "high"

    def test_higher_confidence_middle_span_displaces_two_neighbors(self):
        # A high-confidence span overlapping two lower-confidence spans on either
        # side wins over both.
        left = _mk_span(0, 4, 0.4, "left")
        mid = _mk_span(3, 9, 0.9, "mid")
        right = _mk_span(8, 12, 0.4, "right")
        kept = Span.drop_overlapping_spans([left, mid, right])
        assert [s.filter_type for s in kept] == ["mid"]

    def test_equal_confidence_overlap_keeps_earliest_start(self):
        # Deterministic tie-break: sort by (start, -confidence) then first wins.
        a = _mk_span(0, 5, 0.8, "A")
        b = _mk_span(2, 8, 0.8, "B")
        kept = Span.drop_overlapping_spans([b, a])
        assert len(kept) == 1
        assert kept[0].filter_type == "A"
        assert kept[0].character_start == 0

    def test_adjacent_non_overlapping_both_kept(self):
        a = _mk_span(0, 5, 0.8, "A")
        b = _mk_span(5, 8, 0.8, "B")
        kept = Span.drop_overlapping_spans([a, b])
        assert len(kept) == 2
        assert sorted((s.character_start, s.character_end) for s in kept) == [(0, 5), (5, 8)]

    def test_result_sorted_by_start(self):
        a = _mk_span(10, 12, 0.9, "A")
        b = _mk_span(0, 3, 0.9, "B")
        c = _mk_span(5, 7, 0.9, "C")
        kept = Span.drop_overlapping_spans([a, b, c])
        assert [s.character_start for s in kept] == [0, 5, 10]

    def test_empty_input(self):
        assert Span.drop_overlapping_spans([]) == []

    def test_overlap_via_two_custom_identifiers_one_replacement(self):
        # Two equal-confidence custom identifiers overlap on the same region;
        # the earliest-starting span wins, leaving exactly one replacement.
        identifiers = {
            "identifiers": [
                {"classification": "A", "pattern": r"abcdef",
                 "identifierFilterStrategies": [{"strategy": "REDACT"}]},
                {"classification": "B", "pattern": r"cdefgh",
                 "identifierFilterStrategies": [{"strategy": "REDACT"}]},
            ]
        }
        r = run(identifiers, "zz abcdefgh zz")
        assert "{{{REDACTED-A}}}" in r.filtered_text
        assert "{{{REDACTED-B}}}" not in r.filtered_text
        assert len(r.spans) == 1

    def test_adjacent_custom_identifiers_both_applied(self):
        identifiers = {
            "identifiers": [
                {"classification": "A", "pattern": r"abc",
                 "identifierFilterStrategies": [{"strategy": "STATIC_REPLACE",
                                                 "staticReplacement": "[A]"}]},
                {"classification": "B", "pattern": r"def",
                 "identifierFilterStrategies": [{"strategy": "STATIC_REPLACE",
                                                 "staticReplacement": "[B]"}]},
            ]
        }
        r = run(identifiers, "zz abcdef zz")
        assert r.filtered_text == "zz [A][B] zz"
        assert len(r.spans) == 2


# --------------------------------------------------------------------------
# Referential integrity.
# --------------------------------------------------------------------------
class TestReferentialIntegrity:
    def test_same_token_twice_in_one_doc_identical(self):
        r = run({"ssn": {"ssnFilterStrategies": [{"strategy": "HASH_SHA256_REPLACE"}]}},
                "X 123-45-6789 Y 123-45-6789 Z.")
        assert "123-45-6789" not in r.filtered_text
        hashes = [p for p in r.filtered_text.replace(".", " ").split() if len(p) == 64]
        assert len(hashes) == 2
        assert hashes[0] == hashes[1]
        assert hashes[0] == hashlib.sha256(b"123-45-6789").hexdigest()

    def test_two_filter_calls_same_context_identical(self):
        cs = InMemoryContextService()
        svc = FilterService(cs)
        policy = Policy.from_dict(
            {"name": "t",
             "identifiers": {"ssn": {"ssnFilterStrategies": [{"strategy": "HASH_SHA256_REPLACE"}]}}})
        r1 = svc.filter(policy, "ctx", "d1", "SSN 123-45-6789.")
        r2 = svc.filter(policy, "ctx", "d2", "Again 123-45-6789.")
        h = hashlib.sha256(b"123-45-6789").hexdigest()
        assert h in r1.filtered_text
        assert h in r2.filtered_text

    def test_different_context_independent(self):
        cs = InMemoryContextService()
        cs.put("A", "a@b.com", "SEEDED")
        policy_node = {"emailAddress": {"emailAddressFilterStrategies": [{"strategy": "REDACT"}]}}
        ra = run(policy_node, "Mail a@b.com.", context="A", context_service=cs)
        rb = run(policy_node, "Mail a@b.com.", context="B", context_service=cs)
        assert "SEEDED" in ra.filtered_text
        assert "SEEDED" not in rb.filtered_text
        assert "{{{REDACTED-email-address}}}" in rb.filtered_text

    def test_preseeded_context_forces_replacement(self):
        cs = InMemoryContextService()
        cs.put("ctx", "a@b.com", "PERSISTED")
        r = run({"emailAddress": {"emailAddressFilterStrategies": [{"strategy": "REDACT"}]}},
                "Mail a@b.com now.", context_service=cs)
        assert "PERSISTED" in r.filtered_text
        assert "{{{REDACTED-email-address}}}" not in r.filtered_text

    def test_replacement_cached_into_context_service(self):
        cs = InMemoryContextService()
        run({"ssn": {"ssnFilterStrategies": [{"strategy": "HASH_SHA256_REPLACE"}]}},
            "SSN 123-45-6789.", context_service=cs)
        cached = cs.get("ctx", "123-45-6789")
        assert cached == hashlib.sha256(b"123-45-6789").hexdigest()


# --------------------------------------------------------------------------
# Node-level allowlists.
# --------------------------------------------------------------------------
class TestNodeIgnored:
    def test_node_ignored_term_drops_match(self):
        r = run({"emailAddress": {"emailAddressFilterStrategies": [{"strategy": "REDACT"}],
                                  "ignored": ["noreply@example.com"]}},
                "From noreply@example.com and a@b.com.")
        assert "noreply@example.com" in r.filtered_text
        assert "a@b.com" not in r.filtered_text
        # The ignored term produced no span at all (dropped, not marked).
        assert all(s.text != "noreply@example.com" for s in r.spans)

    def test_node_ignored_pattern_drops_match(self):
        r = run({"ssn": {"ssnFilterStrategies": [{"strategy": "REDACT"}],
                         "ignoredPatterns": [{"pattern": r"123-45-6789"}]}},
                "SSN 123-45-6789 and 456-78-9012.")
        assert "123-45-6789" in r.filtered_text
        assert "456-78-9012" not in r.filtered_text

    def test_node_multiple_ignored_patterns(self):
        r = run({"ssn": {"ssnFilterStrategies": [{"strategy": "REDACT"}],
                         "ignoredPatterns": [{"pattern": r"000-00-0000"},
                                             {"pattern": r"123-45-6789"}]}},
                "A 123-45-6789 B 456-78-9012.")
        assert "123-45-6789" in r.filtered_text
        assert "456-78-9012" not in r.filtered_text

    def test_node_ignored_on_dictionary(self):
        r = run({"dictionaries": [{"classification": "org", "terms": ["Acme", "Globex"],
                                   "ignored": ["Acme"],
                                   "customFilterStrategies": [{"strategy": "REDACT"}]}]},
                "Acme and Globex.")
        assert "Acme" in r.filtered_text
        assert "Globex" not in r.filtered_text


# --------------------------------------------------------------------------
# Policy-level allowlists (mark span ignored, leave text in place).
# --------------------------------------------------------------------------
class TestPolicyIgnored:
    def test_policy_ignored_terms_object_shape_marks_span(self):
        r = run({"emailAddress": {"emailAddressFilterStrategies": [{"strategy": "REDACT"}]}},
                "Mail a@b.com here.",
                policy_extra={"ignored": {"terms": ["a@b.com"]}})
        assert "a@b.com" in r.filtered_text  # left in text
        assert any(s.ignored and s.text == "a@b.com" for s in r.spans)

    def test_policy_ignored_terms_list_of_objects(self):
        r = run({"emailAddress": {"emailAddressFilterStrategies": [{"strategy": "REDACT"}]}},
                "Mail a@b.com here.",
                policy_extra={"ignored": [{"terms": ["a@b.com"]}]})
        assert "a@b.com" in r.filtered_text
        assert any(s.ignored for s in r.spans)

    def test_policy_ignored_pattern_marks_span(self):
        r = run({"emailAddress": {"emailAddressFilterStrategies": [{"strategy": "REDACT"}]}},
                "Mail a@b.com here.",
                policy_extra={"ignoredPatterns": [{"pattern": r".*@b\.com"}]})
        assert "a@b.com" in r.filtered_text
        marked = [s for s in r.spans if s.ignored]
        assert len(marked) == 1
        assert marked[0].text == "a@b.com"

    def test_policy_ignored_pattern_requires_fullmatch(self):
        # A partial pattern does not fullmatch the span text, so the span is
        # still redacted (not marked ignored).
        r = run({"emailAddress": {"emailAddressFilterStrategies": [{"strategy": "REDACT"}]}},
                "Mail a@b.com here.",
                policy_extra={"ignoredPatterns": [{"pattern": r"@b"}]})
        assert "a@b.com" not in r.filtered_text
        assert all(not s.ignored for s in r.spans)


# --------------------------------------------------------------------------
# Node enable/disable and default strategy.
# --------------------------------------------------------------------------
class TestNodeEnableAndDefaults:
    def test_enabled_false_skips_node(self):
        r = run({"emailAddress": {"enabled": False,
                                  "emailAddressFilterStrategies": [{"strategy": "REDACT"}]}},
                "Mail a@b.com here.")
        assert "a@b.com" in r.filtered_text
        assert r.spans == []

    def test_enabled_false_skips_dictionary(self):
        r = run({"dictionaries": [{"classification": "org", "terms": ["Acme"],
                                   "enabled": False,
                                   "customFilterStrategies": [{"strategy": "REDACT"}]}]},
                "Acme here.")
        assert "Acme" in r.filtered_text

    def test_no_strategies_array_defaults_to_redact(self):
        r = run({"emailAddress": {}}, "Mail a@b.com here.")
        assert "{{{REDACTED-email-address}}}" in r.filtered_text

    def test_empty_strategies_array_defaults_to_redact(self):
        r = run({"emailAddress": {"emailAddressFilterStrategies": []}}, "Mail a@b.com here.")
        assert "{{{REDACTED-email-address}}}" in r.filtered_text


# --------------------------------------------------------------------------
# Strategy selection and conditions.
# --------------------------------------------------------------------------
class TestStrategySelection:
    def test_first_passing_condition_wins(self):
        strategies = [
            {"strategy": "STATIC_REPLACE", "staticReplacement": "FIRST",
             "conditions": 'token == "123-45-6789"'},
            {"strategy": "REDACT"},
        ]
        r = run({"ssn": {"ssnFilterStrategies": strategies}}, "SSN 123-45-6789.")
        assert "FIRST" in r.filtered_text
        assert "{{{REDACTED-ssn}}}" not in r.filtered_text

    def test_falls_through_to_second_when_first_fails(self):
        strategies = [
            {"strategy": "STATIC_REPLACE", "staticReplacement": "NOPE",
             "conditions": 'token == "other"'},
            {"strategy": "STATIC_REPLACE", "staticReplacement": "SECOND"},
        ]
        r = run({"ssn": {"ssnFilterStrategies": strategies}}, "SSN 123-45-6789.")
        assert "SECOND" in r.filtered_text
        assert "NOPE" not in r.filtered_text

    def test_no_strategy_condition_passes_drops_span(self):
        strategies = [{"strategy": "REDACT", "conditions": 'token == "never"'}]
        r = run({"ssn": {"ssnFilterStrategies": strategies}}, "SSN 123-45-6789.")
        assert "123-45-6789" in r.filtered_text
        assert r.spans == []

    def test_context_condition(self):
        strategies = [{"strategy": "STATIC_REPLACE", "staticReplacement": "MATCHED",
                       "conditions": 'context == "ctx"'}]
        r = run({"ssn": {"ssnFilterStrategies": strategies}}, "SSN 123-45-6789.")
        assert "MATCHED" in r.filtered_text


# --------------------------------------------------------------------------
# Strategy behaviors (deterministic only).
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "strategy_cfg, expected",
    [
        ({"strategy": "REDACT"}, "{{{REDACTED-ssn}}}"),
        ({"strategy": "REDACT", "redactionFormat": "[X]"}, "[X]"),
        ({"strategy": "MASK", "maskCharacter": "X"}, "XXXXXXXXXXX"),
        ({"strategy": "MASK", "maskCharacter": "#", "maskLength": 4}, "####"),
        ({"strategy": "STATIC_REPLACE", "staticReplacement": "SSN"}, "SSN"),
        ({"strategy": "HASH_SHA256_REPLACE"},
         hashlib.sha256(b"123-45-6789").hexdigest()),
    ],
)
def test_deterministic_strategies(strategy_cfg, expected):
    r = run({"ssn": {"ssnFilterStrategies": [strategy_cfg]}}, "SSN 123-45-6789.")
    assert expected in r.filtered_text
    assert "123-45-6789" not in r.filtered_text


# --------------------------------------------------------------------------
# Combined custom sections (identifiers + dictionaries, no ph-eyes).
# --------------------------------------------------------------------------
class TestCombinedSections:
    def test_builtin_custom_and_dictionary_together(self):
        identifiers = {
            "emailAddress": {"emailAddressFilterStrategies": [{"strategy": "REDACT"}]},
            "identifiers": [{"classification": "MRN", "pattern": r"MRN-\d{6}",
                             "identifierFilterStrategies": [{"strategy": "STATIC_REPLACE",
                                                             "staticReplacement": "[MRN]"}]}],
            "dictionaries": [{"classification": "org", "terms": ["Acme"],
                              "customFilterStrategies": [{"strategy": "REDACT"}]}],
        }
        r = run(identifiers, "Acme mailed a@b.com about MRN-123456.")
        assert "{{{REDACTED-org}}}" in r.filtered_text
        assert "{{{REDACTED-email-address}}}" in r.filtered_text
        assert "[MRN]" in r.filtered_text
        assert "Acme" not in r.filtered_text
        assert "a@b.com" not in r.filtered_text
        assert "MRN-123456" not in r.filtered_text
        assert sorted(s.filter_type for s in r.spans) == ["MRN", "email-address", "org"]

    def test_two_custom_identifiers_distinct_classifications(self):
        identifiers = {
            "identifiers": [
                {"classification": "MRN", "pattern": r"MRN-\d{4}",
                 "identifierFilterStrategies": [{"strategy": "STATIC_REPLACE",
                                                 "staticReplacement": "[MRN]"}]},
                {"classification": "ACCT", "pattern": r"ACCT-\d{4}",
                 "identifierFilterStrategies": [{"strategy": "STATIC_REPLACE",
                                                 "staticReplacement": "[ACCT]"}]},
            ]
        }
        r = run(identifiers, "See MRN-1234 and ACCT-5678 today.")
        assert "[MRN]" in r.filtered_text
        assert "[ACCT]" in r.filtered_text
        assert len(r.spans) == 2


# --------------------------------------------------------------------------
# Result object population.
# --------------------------------------------------------------------------
class TestResultObject:
    def test_result_fields_populated(self):
        r = run({"ssn": {"ssnFilterStrategies": [{"strategy": "REDACT"}]}}, "SSN 123-45-6789.")
        assert r.context == "ctx"
        assert r.document_id == "doc"
        assert isinstance(r.spans, list)
        assert len(r.spans) == 1
        span = r.spans[0]
        assert span.filter_type == "ssn"
        assert span.text == "123-45-6789"
        assert span.replacement == "{{{REDACTED-ssn}}}"

    def test_empty_policy_leaves_text_unchanged(self):
        r = run({}, "Plain text, no PII filters.")
        assert r.filtered_text == "Plain text, no PII filters."
        assert r.spans == []
        assert r.context == "ctx"
        assert r.document_id == "doc"
