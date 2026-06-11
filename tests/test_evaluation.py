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

"""Tests for the evaluation service (precision/recall against ground truth)."""

from phileas.policy.policy import Policy
from phileas.services.evaluation_service import EvaluationService


def _policy():
    return Policy.from_dict({
        "name": "eval",
        "identifiers": {
            "ssn": {"ssnFilterStrategies": [{"strategy": "REDACT"}]},
            "emailAddress": {"emailAddressFilterStrategies": [{"strategy": "REDACT"}]},
        },
    })


class TestEvaluation:
    def test_perfect_match(self):
        text = "SSN 123-45-6789."
        start = text.index("123-45-6789")
        annotations = [{"start": start, "end": start + len("123-45-6789"), "type": "SSN"}]
        result = EvaluationService().evaluate(_policy(), "ctx", "doc", text, annotations)
        assert result.true_positives == 1
        assert result.false_positives == 0
        assert result.false_negatives == 0
        assert result.precision == 1.0
        assert result.recall == 1.0
        assert result.f1 == 1.0

    def test_false_negative(self):
        text = "SSN 123-45-6789 and email a@b.com."
        s2 = text.index("a@b.com")
        annotations = [
            {"start": text.index("123-45-6789"), "end": text.index("123-45-6789") + 11},
            {"start": s2, "end": s2 + len("a@b.com")},
        ]
        policy = Policy.from_dict({"name": "p", "identifiers": {"ssn": {"ssnFilterStrategies": [{"strategy": "REDACT"}]}}})
        result = EvaluationService().evaluate(policy, "ctx", "doc", text, annotations)
        assert result.true_positives == 1
        assert result.false_negatives == 1
        assert result.recall == 0.5

    def test_spans_key_format(self):
        text = "SSN 123-45-6789."
        start = text.index("123-45-6789")
        data = {"text": text, "spans": [{"start": start, "end": start + 11, "type": "SSN"}]}
        result = EvaluationService().evaluate(_policy(), "ctx", "doc", text, data)
        assert result.true_positives == 1
