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

"""The per-strategy ``color`` property: accepted, and inert for text (issue #52)."""

import copy
import warnings

import pytest

from phileas.policy.policy import Policy
from phileas.policy.strategy import Strategy
from phileas.services.filter_service import FilterService

TEXT = "Mail john@example.com, SSN 123-45-6789, born 01/15/1990, card 4111111111111111."

_IDENTIFIERS = {
    "emailAddress": {"emailAddressFilterStrategies": [{"strategy": "REDACT"}]},
    "ssn": {"ssnFilterStrategies": [{"strategy": "MASK", "maskCharacter": "X"}]},
    "date": {"dateFilterStrategies": [{"strategy": "SHIFT", "shiftDays": 3}]},
    "creditCard": {"creditCardFilterStrategies": [{"strategy": "LAST_4"}]},
}


def _policy(color=None):
    identifiers = copy.deepcopy(_IDENTIFIERS)
    if color is not None:
        for node in identifiers.values():
            for strategies in node.values():
                for strategy in strategies:
                    strategy["color"] = color
    return {"name": "p", "identifiers": identifiers}


def _run(policy_dict):
    return FilterService().filter(Policy.from_dict(policy_dict), "c", "d", TEXT)


class TestStrategyModel:
    def test_color_is_accepted(self):
        assert Strategy({"strategy": "REDACT", "color": "red"}).strategy == "REDACT"

    def test_color_round_trips(self):
        assert Strategy({"strategy": "REDACT", "color": "red"}).to_dict() == {
            "strategy": "REDACT", "color": "red"
        }

    def test_replacement_ignores_color(self):
        plain = Strategy({"strategy": "REDACT"})
        colored = Strategy({"strategy": "REDACT", "color": "#FF8800"})
        assert colored.get_replacement("ssn", "123-45-6789") == plain.get_replacement(
            "ssn", "123-45-6789"
        )


class TestTextOutputUnchanged:
    @pytest.mark.parametrize(
        "color",
        [
            # The named set from the schema.
            "black", "white", "red", "orange", "yellow", "green", "blue", "gray",
            # Hex, and values the schema calls malformed. All are inert here.
            "#FF8800", "#ff8800", "puce", "#GGGGGG", "", "0", "black ",
        ],
    )
    def test_output_identical_to_uncoloured_policy(self, color):
        plain, colored = _run(_policy()), _run(_policy(color))
        assert colored.filtered_text == plain.filtered_text
        assert [(s.filter_type, s.text, s.replacement) for s in colored.spans] == [
            (s.filter_type, s.text, s.replacement) for s in plain.spans
        ]

    def test_non_string_color_does_not_break_redaction(self):
        for color in (42, True, ["red"], {"name": "red"}, None):
            assert _run(_policy(color)).filtered_text == _run(_policy()).filtered_text

    def test_no_warning_is_emitted(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _run(_policy("red"))
        assert caught == []

    def test_color_on_one_strategy_of_several(self):
        policy = _policy()
        policy["identifiers"]["ssn"]["ssnFilterStrategies"][0]["color"] = "red"
        assert _run(policy).filtered_text == _run(_policy()).filtered_text


class TestSchemaValidation:
    """A coloured policy validates against the redaction policy schema phisql ships."""

    @staticmethod
    def _schema():
        from phisql import policy_schema

        return policy_schema.get_schema_dict()

    def test_schema_version_is_1_2_0(self):
        from phisql import policy_schema

        assert policy_schema.SUPPORTED_SCHEMA_VERSION == "1.2.0"

    def test_colour_is_declared_on_the_strategy_definitions(self):
        defs = self._schema()["$defs"]
        for name in ("baseFilterStrategy", "dateFilterStrategy"):
            assert "color" in defs[name]["properties"]

    @pytest.mark.parametrize("color", ["red", "#FF8800", "black"])
    def test_coloured_policy_validates(self, color):
        jsonschema = pytest.importorskip("jsonschema")
        # The schema has no top-level `name`, so validate the identifiers document.
        document = {"identifiers": _policy(color)["identifiers"]}
        jsonschema.validate(document, self._schema())

    def test_uncoloured_policy_validates_too(self):
        jsonschema = pytest.importorskip("jsonschema")
        jsonschema.validate({"identifiers": _policy()["identifiers"]}, self._schema())

    @pytest.mark.parametrize("color", ["red", "#FF8800", "black"])
    def test_date_strategy_accepts_colour(self, color):
        # dateFilterStrategy is the closed one, so this is where validation bites.
        jsonschema = pytest.importorskip("jsonschema")
        jsonschema.validate(
            {"identifiers": {"date": {"dateFilterStrategies": [
                {"strategy": "REDACT", "color": color}]}}},
            self._schema(),
        )

    @pytest.mark.parametrize("key", ["colour", "bogus"])
    def test_date_strategy_rejects_an_unknown_property(self, key):
        # The negative control: without it the test above would pass on any key.
        jsonschema = pytest.importorskip("jsonschema")
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(
                {"identifiers": {"date": {"dateFilterStrategies": [
                    {"strategy": "REDACT", key: "red"}]}}},
                self._schema(),
            )

    def test_base_strategy_definition_is_open(self):
        # baseFilterStrategy sets no additionalProperties, so validating a colour
        # there proves nothing on its own; the declaration check above is what counts.
        assert "additionalProperties" not in self._schema()["$defs"]["baseFilterStrategy"]
