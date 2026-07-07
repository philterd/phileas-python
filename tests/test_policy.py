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

"""Tests for Policy parsing of the Phileas/PhiSQL JSON shape."""

import json

import yaml

from phileas.policy.policy import Policy
from phileas.policy.strategy import Strategy


class TestStrategy:
    def test_defaults(self):
        s = Strategy()
        assert s.strategy == "REDACT"

    def test_from_dict(self):
        s = Strategy.from_dict({"strategy": "MASK", "maskCharacter": "#"})
        assert s.strategy == "MASK"
        assert s.config["maskCharacter"] == "#"

    def test_conditions_exposed(self):
        s = Strategy.from_dict({"strategy": "MASK", "condition": "confidence > 0.5"})
        assert s.condition == "confidence > 0.5"
        assert s.evaluate_condition("t", "c", 0.9) is True
        assert s.evaluate_condition("t", "c", 0.1) is False

    def test_default_factory(self):
        assert Strategy.default().strategy == "REDACT"


class TestPolicy:
    def test_default(self):
        p = Policy()
        assert p.name == "default"
        assert p.identifiers == {}
        assert p.ignored == []
        assert p.ignored_patterns == []

    def test_identifiers_kept_raw(self):
        d = {
            "name": "p",
            "identifiers": {"ssn": {"ssnFilterStrategies": [{"strategy": "REDACT"}]}},
        }
        p = Policy.from_dict(d)
        assert p.identifiers["ssn"]["ssnFilterStrategies"][0]["strategy"] == "REDACT"

    def test_ignored_phisql_object_shape(self):
        # PhiSQL compiles scope-less IGNORE TERMS to a list of {terms:[...]} objects.
        d = {"identifiers": {}, "ignored": [{"terms": ["Acme Corp", "Test User"]}]}
        p = Policy.from_dict(d)
        assert p.ignored == ["Acme Corp", "Test User"]

    def test_ignored_plain_string_list(self):
        d = {"identifiers": {}, "ignored": ["noreply@example.com"]}
        p = Policy.from_dict(d)
        assert p.ignored == ["noreply@example.com"]

    def test_ignored_patterns_object_shape(self):
        d = {"identifiers": {}, "ignoredPatterns": [{"pattern": r"\d{3}-test"}]}
        p = Policy.from_dict(d)
        assert p.ignored_patterns == [r"\d{3}-test"]

    def test_from_json(self):
        p = Policy.from_json(json.dumps({"name": "j", "identifiers": {"age": {}}}))
        assert p.name == "j"
        assert "age" in p.identifiers

    def test_from_yaml(self):
        p = Policy.from_yaml("name: y\nidentifiers:\n  ssn: {}\n")
        assert p.name == "y"
        assert "ssn" in p.identifiers

    def test_json_round_trip(self):
        d = {"name": "rt", "identifiers": {"ssn": {"ssnFilterStrategies": [{"strategy": "MASK"}]}}}
        p = Policy.from_dict(d)
        p2 = Policy.from_json(p.to_json())
        assert p2.name == "rt"
        assert p2.identifiers["ssn"]["ssnFilterStrategies"][0]["strategy"] == "MASK"

    def test_to_dict_reemits_ignored_objects(self):
        p = Policy.from_dict({"identifiers": {}, "ignored": ["a", "b"]})
        out = p.to_dict()
        assert out["ignored"] == [{"terms": ["a", "b"]}]

    def test_yaml_round_trip_ignored_patterns(self):
        p = Policy.from_dict({"identifiers": {}, "ignoredPatterns": [{"pattern": r"\d+"}]})
        assert Policy.from_yaml(p.to_yaml()).ignored_patterns == [r"\d+"]
