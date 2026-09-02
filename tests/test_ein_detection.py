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

"""Characterization tests for :class:`EINFilter` detection."""

import pytest

from phileas.filters.ein_filter import EINFilter
from phileas.filters.ssn_filter import SSNFilter
from phileas.policy.policy import Policy
from phileas.services.filter_service import FilterService


def _texts(spans):
    return [s.text for s in spans]


def run(identifiers, text, context="ctx"):
    policy = Policy.from_dict({"name": "t", "identifiers": identifiers})
    return FilterService().filter(policy, context, "doc", text)


class TestEINPositive:
    def test_canonical_ein_detected(self):
        spans = EINFilter().detect("the ein is 12-3456789.")
        assert len(spans) == 1
        span = spans[0]
        assert span.text == "12-3456789"
        assert span.filter_type == "ein"
        assert span.confidence == 1.0
        assert span.replacement == ""
        assert span.character_start == 11
        assert span.character_end == 21

    def test_offsets_match_source_text(self):
        text = "Tax ID 45-0123456 on file."
        span = EINFilter().detect(text)[0]
        assert text[span.character_start:span.character_end] == span.text

    @pytest.mark.parametrize(
        "value",
        ["12-3456789", "01-0000001", "99-9999999", "45-0123456", "07-1234567"],
    )
    def test_valid_shapes_detected(self, value):
        assert _texts(EINFilter().detect(f"EIN {value} here")) == [value]

    def test_two_eins_in_one_document(self):
        spans = EINFilter().detect("12-3456789 and 98-7654321")
        assert _texts(spans) == ["12-3456789", "98-7654321"]

    def test_filter_type_is_ein(self):
        assert EINFilter().filter_type == "ein"

    def test_default_config_construction(self):
        assert EINFilter().config == {}
        assert EINFilter(None).config == {}


class TestEINBoundaries:
    @pytest.mark.parametrize(
        "text",
        [
            # A bare nine-digit run is ambiguous with SSN, so EIN does not claim it.
            "the number is 123456789.",
            # Wrong hyphen position: that is an SSN's shape, not an EIN's.
            "the ssn is 123-45-6789.",
            # Too many or too few digits on either side of the hyphen.
            "12-34567890",
            "112-3456789",
            "1-3456789",
            "12-345678",
            # The hyphen is required.
            "12 3456789",
            "123456789",
            # Digits running into surrounding word characters.
            "x12-3456789",
            "12-3456789x",
            "",
        ],
    )
    def test_not_detected(self, text):
        assert EINFilter().detect(text) == []


class TestSSNDistinction:
    """Both filters claim ``NN-NNNNNNN``; ein outranks ssn on it. See issue #64."""

    def test_ssn_claims_the_tin_form_at_lower_confidence(self):
        spans = SSNFilter().detect("12-3456789")
        assert [s.text for s in spans] == ["12-3456789"]
        assert spans[0].confidence == 0.90

    def test_ein_claims_the_same_form_at_full_confidence(self):
        spans = EINFilter().detect("12-3456789")
        assert [s.text for s in spans] == ["12-3456789"]
        assert spans[0].confidence == 1.0

    def test_ssn_form_is_not_an_ein(self):
        assert EINFilter().detect("123-45-6789") == []

    def test_bare_run_goes_to_ssn_alone(self):
        text = "the number is 123456789."
        assert _texts(SSNFilter().detect(text)) == ["123456789"]
        assert EINFilter().detect(text) == []

    def test_both_enabled_each_claims_its_own_form(self):
        r = run(
            {
                "ein": {"einFilterStrategies": [{"strategy": "REDACT"}]},
                "ssn": {"ssnFilterStrategies": [{"strategy": "REDACT"}]},
            },
            "EIN 12-3456789 and SSN 123-45-6789.",
        )
        by_type = {s.filter_type: s.text for s in r.spans}
        assert by_type == {"ein": "12-3456789", "ssn": "123-45-6789"}

    def test_ein_wins_the_tin_form_when_both_are_enabled(self):
        r = run(
            {
                "ein": {"einFilterStrategies": [{"strategy": "REDACT"}]},
                "ssn": {"ssnFilterStrategies": [{"strategy": "REDACT"}]},
            },
            "Tax ID 12-3456789.",
        )
        assert [(s.filter_type, s.text) for s in r.spans] == [("ein", "12-3456789")]

    def test_ssn_alone_still_redacts_the_tin_form(self):
        r = run({"ssn": {"ssnFilterStrategies": [{"strategy": "REDACT"}]}},
                "Tax ID 12-3456789.")
        assert [(s.filter_type, s.text) for s in r.spans] == [("ssn", "12-3456789")]
        assert "12-3456789" not in r.filtered_text

    def test_both_enabled_bare_run_is_ssn(self):
        r = run(
            {
                "ein": {"einFilterStrategies": [{"strategy": "REDACT"}]},
                "ssn": {"ssnFilterStrategies": [{"strategy": "REDACT"}]},
            },
            "the number is 123456789.",
        )
        assert [(s.filter_type, s.text) for s in r.spans] == [("ssn", "123456789")]


class TestOnlyValidPrefixes:
    """``onlyValidPrefixes`` keeps only prefixes the IRS issues. Off by default."""

    def test_default_is_off(self):
        # 07 is not an IRS-issued prefix, and is kept when the option is absent.
        assert _texts(EINFilter().detect("the ein is 07-1234567.")) == ["07-1234567"]

    def test_explicit_false_keeps_invalid_prefix(self):
        f = EINFilter({"onlyValidPrefixes": False})
        assert _texts(f.detect("the ein is 07-1234567.")) == ["07-1234567"]

    @pytest.mark.parametrize("value", ["07-1234567", "08-1234567", "09-1234567", "17-1234567",
                                       "28-1234567", "49-1234567", "69-1234567", "70-1234567",
                                       "78-1234567", "79-1234567", "89-1234567", "96-1234567",
                                       "97-1234567", "00-1234567"])
    def test_on_drops_unissued_prefix(self, value):
        assert EINFilter({"onlyValidPrefixes": True}).detect(f"EIN {value}") == []

    @pytest.mark.parametrize("value", ["01-1234567", "12-3456789", "35-1234567", "48-1234567",
                                       "59-1234567", "68-1234567", "77-1234567", "88-1234567",
                                       "95-1234567", "99-1234567"])
    def test_on_keeps_issued_prefix(self, value):
        assert _texts(EINFilter({"onlyValidPrefixes": True}).detect(f"EIN {value}")) == [value]

    def test_on_filters_a_mixed_document(self):
        text = "12-3456789 is issued, 07-1234567 is not."
        assert _texts(EINFilter({"onlyValidPrefixes": True}).detect(text)) == ["12-3456789"]

    def test_option_reaches_the_filter_through_the_policy(self):
        r = run(
            {"ein": {"onlyValidPrefixes": True, "einFilterStrategies": [{"strategy": "REDACT"}]}},
            "EIN 07-1234567 here.",
        )
        assert r.spans == []
        assert "07-1234567" in r.filtered_text


class TestEINPolicy:
    """A policy with ``identifiers.ein`` loads and redacts through the catalog."""

    def test_default_strategy_redacts(self):
        r = run({"ein": {}}, "EIN 12-3456789 here.")
        assert "12-3456789" not in r.filtered_text
        assert "{{{REDACTED-ein}}}" in r.filtered_text

    def test_disabled_node_skipped(self):
        r = run({"ein": {"enabled": False}}, "EIN 12-3456789 here.")
        assert "12-3456789" in r.filtered_text

    def test_mask_strategy_applied(self):
        r = run(
            {"ein": {"einFilterStrategies": [{"strategy": "MASK", "maskCharacter": "*"}]}},
            "EIN 12-3456789 here.",
        )
        assert "**********" in r.filtered_text
        assert "12-3456789" not in r.filtered_text

    def test_static_replace_strategy_applied(self):
        r = run(
            {"ein": {"einFilterStrategies": [
                {"strategy": "STATIC_REPLACE", "staticReplacement": "00-0000000"}
            ]}},
            "EIN 12-3456789 here.",
        )
        assert "00-0000000" in r.filtered_text

    def test_ignored_term_is_kept(self):
        r = run(
            {"ein": {"ignored": ["12-3456789"], "einFilterStrategies": [{"strategy": "REDACT"}]}},
            "EIN 12-3456789 here.",
        )
        assert "12-3456789" in r.filtered_text


class TestEINRandomReplace:
    """Without a registered anonymization service the token passes through unredacted."""

    def test_random_replace_changes_the_value(self):
        r = run(
            {"ein": {"einFilterStrategies": [{"strategy": "RANDOM_REPLACE"}]}},
            "EIN 12-3456789 here.",
        )
        assert "12-3456789" not in r.filtered_text

    def test_replacement_is_ein_shaped(self):
        import re

        from phileas.services.anonymization import get_anonymization_service

        service = get_anonymization_service("ein")
        assert service is not None
        for _ in range(50):
            assert re.fullmatch(r"\d{2}-\d{7}", service.anonymize("12-3456789"))

    def test_replacement_prefix_is_always_issued(self):
        from phileas.filters.ein_filter import VALID_PREFIXES
        from phileas.services.anonymization import get_anonymization_service

        service = get_anonymization_service("ein")
        for _ in range(200):
            assert service.anonymize("12-3456789")[:2] in VALID_PREFIXES


class TestHyphenBoundaries:
    """A neighbouring hyphen means the digits belong to a longer identifier."""

    @pytest.mark.parametrize(
        "text",
        [
            "12-3456789-01",
            "ID-12-3456789",
            "-12-3456789",
            "12-3456789-",
            "2026-12-3456789",
            # philterd/phileas#343: "45-6789123" used to match inside this.
            "123-45-6789123-45-6789",
        ],
    )
    def test_hyphenated_neighbour_is_not_an_ein(self, text):
        assert EINFilter().detect(text) == []

    @pytest.mark.parametrize(
        "text,expected",
        [
            ("12-3456789", "12-3456789"),
            ("EIN: 12-3456789.", "12-3456789"),
            ("(12-3456789)", "12-3456789"),
            ("12-3456789, paid", "12-3456789"),
        ],
    )
    def test_ordinary_punctuation_still_delimits(self, text, expected):
        assert _texts(EINFilter().detect(text)) == [expected]

    def test_ssn_filter_still_claims_its_own_hyphenated_head(self):
        # SSNFilter keeps the looser boundary; see issue #64.
        assert _texts(SSNFilter().detect("123-45-6789-01")) == ["123-45-6789"]
