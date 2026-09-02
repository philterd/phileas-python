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

"""The policy ``config`` object and its ``analysis`` flags."""

import json

import pytest
import yaml

from phileas.policy.policy import Policy
from phileas.services.filter_service import FilterService

TEXT = "Mail john@example.com, SSN 123-45-6789."

IDENTIFIERS = {
    "emailAddress": {"emailAddressFilterStrategies": [{"strategy": "REDACT"}]},
    "ssn": {"ssnFilterStrategies": [{"strategy": "REDACT"}]},
}


def policy(config=None):
    data = {"name": "p", "identifiers": IDENTIFIERS}
    if config is not None:
        data["config"] = config
    return Policy.from_dict(data)


class TestAnalysisFlags:
    def test_default_is_true(self):
        assert policy().span_disambiguation is True
        assert policy().identification is True

    def test_empty_analysis_defaults_to_true(self):
        assert policy({"analysis": {}}).span_disambiguation is True

    def test_false_is_read(self):
        assert policy({"analysis": {"spanDisambiguation": False}}).span_disambiguation is False

    def test_true_is_read(self):
        assert policy({"analysis": {"spanDisambiguation": True}}).span_disambiguation is True

    def test_identification_is_read_independently(self):
        p = policy({"analysis": {"identification": False, "spanDisambiguation": True}})
        assert p.identification is False
        assert p.span_disambiguation is True

    @pytest.mark.parametrize("value", ["false", 0, None, [], {"a": 1}])
    def test_a_non_boolean_falls_back_to_the_default(self, value):
        assert policy({"analysis": {"spanDisambiguation": value}}).span_disambiguation is True

    @pytest.mark.parametrize("config", [{"analysis": "yes"}, {"analysis": []},
                                        {"analysis": None}, "notadict", ["a"], 42])
    def test_a_malformed_config_reads_as_the_default(self, config):
        assert policy(config).span_disambiguation is True
        assert policy(config).identification is True

    @pytest.mark.parametrize("config", [{"analysis": "yes"}, "notadict", 42])
    def test_a_malformed_config_is_still_round_tripped(self, config):
        assert policy(config).to_dict()["config"] == config


class TestRoundTrip:
    def test_config_survives_to_dict(self):
        config = {"analysis": {"spanDisambiguation": False}}
        assert policy(config).to_dict()["config"] == config

    def test_absent_config_is_not_invented(self):
        assert "config" not in policy().to_dict()

    def test_the_whole_config_is_kept_not_just_analysis(self):
        config = {
            "analysis": {"spanDisambiguation": False},
            "splitting": {"enabled": True, "method": "newline"},
            "postFilters": {"removeTrailingPeriods": False},
        }
        assert policy(config).to_dict()["config"] == config

    def test_json_round_trip(self):
        config = {"analysis": {"spanDisambiguation": False}}
        restored = Policy.from_json(json.dumps(policy(config).to_dict()))
        assert restored.config == config
        assert restored.span_disambiguation is False

    def test_yaml_round_trip(self):
        config = {"analysis": {"spanDisambiguation": False}}
        restored = Policy.from_yaml(yaml.dump(policy(config).to_dict()))
        assert restored.config == config
        assert restored.span_disambiguation is False

    def test_an_unknown_config_key_is_preserved(self):
        config = {"future": {"setting": 1}}
        assert policy(config).to_dict()["config"] == config


class TestNoBehaviourChange:
    """No disambiguation step exists, so the flag cannot alter output."""

    @pytest.mark.parametrize(
        "config",
        [None, {}, {"analysis": {"spanDisambiguation": True}},
         {"analysis": {"spanDisambiguation": False}}],
    )
    def test_output_is_the_same_whatever_the_flag_says(self, config):
        plain = FilterService().filter(policy(), "c", "d", TEXT)
        result = FilterService().filter(policy(config), "c", "d", TEXT)
        assert result.filtered_text == plain.filtered_text
        assert [(s.filter_type, s.text) for s in result.spans] == [
            (s.filter_type, s.text) for s in plain.spans
        ]


class TestSchema:
    def test_a_policy_with_the_flag_validates(self):
        jsonschema = pytest.importorskip("jsonschema")
        from phisql import policy_schema

        document = {"config": {"analysis": {"spanDisambiguation": False,
                                            "identification": True}},
                    "identifiers": IDENTIFIERS}
        jsonschema.validate(document, policy_schema.get_schema_dict())

    def test_an_unknown_analysis_key_is_rejected_by_the_schema(self):
        jsonschema = pytest.importorskip("jsonschema")
        from phisql import policy_schema

        document = {"config": {"analysis": {"spanDisambiguationn": False}}}
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(document, policy_schema.get_schema_dict())
