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

"""Deeper characterization tests for Policy and Strategy parsing."""

import json

import pytest
import yaml

from phileas.actions import DEFAULT_REDACTION_FORMAT
from phileas.policy.policy import Policy
from phileas.policy.strategy import Strategy


class TestPolicyIgnored:
    def test_ignored_list_of_objects(self):
        d = {"ignored": [{"terms": ["Acme", "Corp"]}, {"terms": ["Other"]}]}
        p = Policy.from_dict(d)
        assert p.ignored == ["Acme", "Corp", "Other"]

    def test_ignored_list_of_strings(self):
        p = Policy.from_dict({"ignored": ["alpha", "beta"]})
        assert p.ignored == ["alpha", "beta"]

    def test_ignored_single_dict(self):
        # A single {terms:[...]} object (not wrapped in a list) is accepted.
        p = Policy.from_dict({"ignored": {"terms": ["x", "y"]}})
        assert p.ignored == ["x", "y"]

    def test_ignored_empty_list(self):
        assert Policy.from_dict({"ignored": []}).ignored == []

    def test_ignored_missing(self):
        assert Policy.from_dict({}).ignored == []

    def test_ignored_mixed_strings_and_objects(self):
        d = {"ignored": ["lone", {"terms": ["a", "b"]}]}
        assert Policy.from_dict(d).ignored == ["lone", "a", "b"]

    def test_ignored_object_without_terms_key(self):
        # An object lacking "terms" contributes nothing.
        assert Policy.from_dict({"ignored": [{}]}).ignored == []

    def test_ignored_object_null_terms(self):
        assert Policy.from_dict({"ignored": [{"terms": None}]}).ignored == []


class TestPolicyIgnoredPatterns:
    def test_patterns_list_of_objects(self):
        d = {"ignoredPatterns": [{"pattern": r"\d+"}, {"pattern": r"[a-z]+"}]}
        assert Policy.from_dict(d).ignored_patterns == [r"\d+", r"[a-z]+"]

    def test_patterns_list_of_strings(self):
        p = Policy.from_dict({"ignoredPatterns": [r"\w+", r"\s+"]})
        assert p.ignored_patterns == [r"\w+", r"\s+"]

    def test_patterns_single_dict(self):
        assert Policy.from_dict({"ignoredPatterns": {"pattern": "abc"}}).ignored_patterns == ["abc"]

    def test_patterns_missing(self):
        assert Policy.from_dict({}).ignored_patterns == []

    def test_patterns_empty_value_dropped(self):
        # A falsy pattern value is skipped.
        d = {"ignoredPatterns": [{"pattern": ""}, {"pattern": "z"}]}
        assert Policy.from_dict(d).ignored_patterns == ["z"]

    def test_patterns_object_without_pattern_key(self):
        assert Policy.from_dict({"ignoredPatterns": [{}]}).ignored_patterns == []


class TestPolicyIdentifiersAndName:
    def test_identifiers_kept_raw(self):
        ident = {
            "ssn": {"ssnFilterStrategies": [{"strategy": "REDACT", "condition": "x"}]},
            "age": {"ageFilterStrategies": []},
        }
        p = Policy.from_dict({"identifiers": ident})
        # The raw dict is preserved untouched.
        assert p.identifiers == ident
        assert p.identifiers["ssn"]["ssnFilterStrategies"][0]["condition"] == "x"

    def test_identifiers_missing_defaults_empty(self):
        assert Policy.from_dict({}).identifiers == {}

    def test_identifiers_null_defaults_empty(self):
        assert Policy.from_dict({"identifiers": None}).identifiers == {}

    def test_name_default(self):
        assert Policy.from_dict({}).name == "default"

    def test_name_from_data(self):
        assert Policy.from_dict({"name": "custom"}).name == "custom"

    def test_constructor_defaults(self):
        p = Policy()
        assert p.name == "default"
        assert p.identifiers == {}
        assert p.ignored == []
        assert p.ignored_patterns == []


class TestPolicyFromSerialized:
    def test_from_json(self):
        p = Policy.from_json(json.dumps({"name": "j", "identifiers": {"age": {}}}))
        assert p.name == "j"
        assert "age" in p.identifiers

    def test_from_yaml(self):
        p = Policy.from_yaml("name: y\nidentifiers:\n  ssn: {}\n")
        assert p.name == "y"
        assert "ssn" in p.identifiers

    def test_from_json_parses_ignored(self):
        p = Policy.from_json(json.dumps({"ignored": [{"terms": ["a"]}]}))
        assert p.ignored == ["a"]

    def test_from_yaml_parses_patterns(self):
        text = yaml.safe_dump({"ignoredPatterns": [{"pattern": r"\d+"}]})
        p = Policy.from_yaml(text)
        assert p.ignored_patterns == [r"\d+"]


class TestPolicyToDict:
    def test_to_dict_reemits_ignored_objects(self):
        p = Policy.from_dict({"ignored": ["a", "b"]})
        assert p.to_dict()["ignored"] == [{"terms": ["a", "b"]}]

    def test_to_dict_empty_ignored_is_empty_list(self):
        assert Policy().to_dict()["ignored"] == []

    def test_to_dict_reemits_patterns_objects(self):
        p = Policy.from_dict({"ignoredPatterns": [r"\d+", r"\w+"]})
        assert p.to_dict()["ignoredPatterns"] == [{"pattern": r"\d+"}, {"pattern": r"\w+"}]

    def test_to_dict_empty_patterns_is_empty_list(self):
        assert Policy().to_dict()["ignoredPatterns"] == []

    def test_to_dict_keys(self):
        out = Policy().to_dict()
        assert set(out.keys()) == {"name", "identifiers", "ignored", "ignoredPatterns"}

    def test_to_dict_carries_name_and_identifiers(self):
        p = Policy.from_dict({"name": "n", "identifiers": {"k": {"v": 1}}})
        out = p.to_dict()
        assert out["name"] == "n"
        assert out["identifiers"] == {"k": {"v": 1}}


class TestPolicyRoundTrips:
    def _rich(self):
        return {
            "name": "rt",
            "identifiers": {
                "ssn": {"ssnFilterStrategies": [{"strategy": "MASK", "maskCharacter": "#"}]},
                "age": {"ageFilterStrategies": [{"strategy": "REDACT"}]},
            },
            "ignored": [{"terms": ["Acme", "Corp"]}],
            "ignoredPatterns": [{"pattern": r"\d{3}-x"}],
        }

    def test_json_round_trip_preserves_identifiers(self):
        p = Policy.from_json(json.dumps(self._rich()))
        p2 = Policy.from_json(p.to_json())
        assert p2.name == "rt"
        assert p2.identifiers["ssn"]["ssnFilterStrategies"][0]["maskCharacter"] == "#"
        assert p2.identifiers["age"]["ageFilterStrategies"][0]["strategy"] == "REDACT"

    def test_json_round_trip_preserves_allowlists(self):
        p = Policy.from_dict(self._rich())
        p2 = Policy.from_json(p.to_json())
        assert p2.ignored == ["Acme", "Corp"]
        assert p2.ignored_patterns == [r"\d{3}-x"]

    def test_yaml_round_trip_preserves_identifiers(self):
        p = Policy.from_dict(self._rich())
        p2 = Policy.from_yaml(p.to_yaml())
        assert p2.identifiers["ssn"]["ssnFilterStrategies"][0]["maskCharacter"] == "#"

    def test_yaml_round_trip_preserves_allowlists(self):
        p = Policy.from_dict(self._rich())
        p2 = Policy.from_yaml(p.to_yaml())
        assert p2.ignored == ["Acme", "Corp"]
        assert p2.ignored_patterns == [r"\d{3}-x"]

    def test_to_dict_round_trip_idempotent_dict(self):
        p = Policy.from_dict(self._rich())
        # Re-parsing the emitted dict yields equal normalized fields.
        p2 = Policy.from_dict(p.to_dict())
        assert p2.ignored == p.ignored
        assert p2.ignored_patterns == p.ignored_patterns
        assert p2.identifiers == p.identifiers
        assert p2.name == p.name


class TestStrategy:
    def test_default_strategy_redact(self):
        s = Strategy()
        assert s.strategy == "REDACT"
        assert s.config == {"strategy": "REDACT"}

    def test_none_config_defaults_redact(self):
        assert Strategy(None).strategy == "REDACT"

    def test_empty_config_defaults_redact(self):
        # A falsy config falls back to the default REDACT config.
        assert Strategy({}).config == {"strategy": "REDACT"}

    def test_from_dict(self):
        s = Strategy.from_dict({"strategy": "MASK", "maskCharacter": "#"})
        assert s.strategy == "MASK"
        assert s.config["maskCharacter"] == "#"

    def test_default_factory(self):
        s = Strategy.default()
        assert s.strategy == "REDACT"
        assert s.config["redactionFormat"] == DEFAULT_REDACTION_FORMAT

    def test_conditions_default_empty(self):
        assert Strategy({"strategy": "MASK"}).condition == ""

    def test_conditions_null_normalized_to_empty(self):
        assert Strategy({"strategy": "MASK", "condition": None}).condition == ""

    def test_conditions_exposed(self):
        s = Strategy.from_dict({"strategy": "MASK", "condition": "confidence > 0.5"})
        assert s.condition == "confidence > 0.5"

    def test_canonical_condition_key_honored(self):
        # `condition` (singular) is the canonical key (schema + Java/.NET runtimes).
        s = Strategy.from_dict({"strategy": "REDACT", "condition": 'token == "x"'})
        assert s.condition == 'token == "x"'
        assert s.evaluate_condition("x", "c", 1.0) is True
        assert s.evaluate_condition("y", "c", 1.0) is False

    def test_deprecated_plural_conditions_alias(self):
        # `conditions` (plural) is accepted as a deprecated alias.
        s = Strategy.from_dict({"strategy": "REDACT", "conditions": "confidence > 0.5"})
        assert s.condition == "confidence > 0.5"
        assert s.evaluate_condition("t", "c", 0.9) is True

    def test_singular_condition_wins_over_plural_alias(self):
        s = Strategy.from_dict({
            "strategy": "REDACT",
            "condition": "confidence > 0.5",
            "conditions": "confidence > 0.9",
        })
        assert s.condition == "confidence > 0.5"

    def test_to_dict_copies_config(self):
        s = Strategy({"strategy": "X", "a": 1})
        out = s.to_dict()
        assert out == {"strategy": "X", "a": 1}
        out["a"] = 99
        # Mutating the returned dict must not affect the strategy.
        assert s.config["a"] == 1

    def test_constructor_copies_input_config(self):
        src = {"strategy": "MASK", "a": 1}
        s = Strategy(src)
        src["a"] = 99
        assert s.config["a"] == 1

    @pytest.mark.parametrize("name", ["MASK", "REDACT", "ENCRYPT", "HASH", "RANDOM"])
    def test_strategy_name_passthrough(self, name):
        assert Strategy({"strategy": name}).strategy == name
