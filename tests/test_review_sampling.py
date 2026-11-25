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

"""The policy's ``config.review.samplingRate`` and ``FilterResult.review_sampled``."""

import json
import random

import pytest
import yaml

from phileas.policy.policy import Policy
from phileas.services import review_sampler
from phileas.services.filter_service import FilterService

TEXT = "Mail john@example.com, SSN 123-45-6789."


def policy(rate=None, strategy="REDACT"):
    data = {
        "name": "p",
        "identifiers": {
            "emailAddress": {"emailAddressFilterStrategies": [{"strategy": strategy}]},
            "ssn": {"ssnFilterStrategies": [{"strategy": strategy}]},
        },
    }
    if rate is not None:
        data["config"] = {"review": {"samplingRate": rate}}
    return Policy.from_dict(data)


class TestPolicySetting:
    def test_defaults_to_zero_when_absent(self):
        assert policy().review_sampling_rate == 0.0

    def test_defaults_to_zero_when_review_is_empty(self):
        p = Policy.from_dict({"name": "p", "config": {"review": {}}})
        assert p.review_sampling_rate == 0.0

    @pytest.mark.parametrize("rate", [0, 0.0, 0.1, 0.5, 1, 1.0])
    def test_is_read(self, rate):
        assert policy(rate).review_sampling_rate == float(rate)

    def test_round_trips_through_json(self):
        p = Policy.from_json(policy(0.1).to_json())
        assert p.review_sampling_rate == 0.1
        assert p.to_dict()["config"] == {"review": {"samplingRate": 0.1}}

    def test_round_trips_through_yaml(self):
        p = Policy.from_yaml(policy(0.25).to_yaml())
        assert p.review_sampling_rate == 0.25
        assert yaml.safe_load(p.to_yaml())["config"] == {"review": {"samplingRate": 0.25}}

    def test_absent_is_not_written(self):
        assert "config" not in policy().to_dict()

    @pytest.mark.parametrize(
        "rate", [-0.01, 1.01, 2, float("nan"), float("inf"), "0.1", True, [0.1]]
    )
    def test_invalid_rate_is_a_load_error(self, rate):
        with pytest.raises(ValueError, match="samplingRate"):
            policy(rate)

    def test_null_rate_is_a_load_error(self):
        with pytest.raises(ValueError, match="samplingRate"):
            Policy.from_dict({"name": "p", "config": {"review": {"samplingRate": None}}})

    def test_invalid_rate_in_json_is_a_load_error(self):
        data = {"name": "p", "config": {"review": {"samplingRate": 1.5}}}
        with pytest.raises(ValueError, match="samplingRate"):
            Policy.from_json(json.dumps(data))

    def test_non_object_review_is_a_load_error(self):
        with pytest.raises(ValueError, match="config.review"):
            Policy.from_dict({"name": "p", "config": {"review": 0.1}})

    def test_rate_changed_after_load_is_checked_when_filtering(self):
        p = policy(0.1)
        p.config["review"]["samplingRate"] = 5
        with pytest.raises(ValueError, match="samplingRate"):
            FilterService().filter(p, "ctx", "doc", TEXT)


class TestSampler:
    def test_zero_never_selects_or_draws(self):
        def draw():
            raise AssertionError("drew for a rate of 0.0")

        assert review_sampler.is_selected(policy(0.0), draw) is False

    def test_one_always_selects_without_drawing(self):
        def draw():
            raise AssertionError("drew for a rate of 1.0")

        assert review_sampler.is_selected(policy(1.0), draw) is True

    def test_absent_never_selects(self):
        assert review_sampler.is_selected(policy(), lambda: 0.0) is False

    def test_selects_when_draw_is_below_rate(self):
        assert review_sampler.is_selected(policy(0.1), lambda: 0.0999) is True

    def test_does_not_select_when_draw_equals_rate(self):
        assert review_sampler.is_selected(policy(0.1), lambda: 0.1) is False

    def test_does_not_select_when_draw_is_above_rate(self):
        assert review_sampler.is_selected(policy(0.1), lambda: 0.5) is False


class TestFilterResult:
    def test_absent_is_not_sampled(self):
        assert FilterService().filter(policy(), "ctx", "doc", TEXT).review_sampled is False

    def test_zero_never_selects(self):
        service = FilterService()
        assert not any(
            service.filter(policy(0.0), "ctx", "doc", TEXT).review_sampled for _ in range(200)
        )

    def test_one_always_selects(self):
        service = FilterService()
        assert all(
            service.filter(policy(1.0), "ctx", "doc", TEXT).review_sampled for _ in range(200)
        )

    def test_selection_does_not_change_redacted_output(self):
        service = FilterService()
        unsampled = service.filter(policy(0.0), "ctx", "doc", TEXT)
        sampled = service.filter(policy(1.0), "ctx", "doc", TEXT)
        assert unsampled.review_sampled is False
        assert sampled.review_sampled is True
        assert sampled.filtered_text == unsampled.filtered_text
        assert [(s.character_start, s.character_end, s.replacement) for s in sampled.spans] == [
            (s.character_start, s.character_end, s.replacement) for s in unsampled.spans
        ]

    def test_drawing_does_not_change_random_replacements(self):
        # A rate strictly between 0 and 1 draws. The draw must not consume the
        # random state anonymization uses, or RANDOM_REPLACE output would shift.
        random.seed(1234)
        without_draw = FilterService().filter(
            policy(0.0, "RANDOM_REPLACE"), "ctx", "doc", TEXT
        ).filtered_text
        random.seed(1234)
        with_draw = FilterService().filter(
            policy(0.5, "RANDOM_REPLACE"), "ctx", "doc", TEXT
        ).filtered_text
        assert with_draw == without_draw
        assert "123-45-6789" not in with_draw


class TestPhiSQL:
    def test_configure_review_compiles_and_loads(self):
        from phisql import Compiler

        compiled = Compiler().compile(
            "POLICY p; DEIDENTIFY SSN AS REDACT; CONFIGURE REVIEW (samplingRate = 1.0);"
        ).policy_json()
        result = FilterService().filter(Policy.from_dict(compiled), "ctx", "doc", TEXT)
        assert result.review_sampled is True
        assert "123-45-6789" not in result.filtered_text
