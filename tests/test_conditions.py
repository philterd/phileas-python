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

"""Tests for the strategy condition evaluator."""

import pytest

from phileas.policy.conditions import evaluate


class TestConditionEvaluator:
    def test_empty_condition_always_true(self):
        assert evaluate("", "x", "ctx", 1.0) is True
        assert evaluate("   ", "x", "ctx", 1.0) is True

    @pytest.mark.parametrize("cond,conf,expected", [
        ("confidence > 0.5", 0.9, True),
        ("confidence > 0.5", 0.4, False),
        ("confidence >= 0.9", 0.9, True),
        ("confidence < 0.2", 0.1, True),
        ("confidence == 0.5", 0.5, True),
        ("confidence != 0.5", 0.6, True),
    ])
    def test_confidence(self, cond, conf, expected):
        assert evaluate(cond, "tok", "ctx", conf) is expected

    def test_and(self):
        assert evaluate("confidence > 0.5 and confidence < 0.95", "t", "c", 0.7) is True
        assert evaluate("confidence > 0.5 and confidence < 0.95", "t", "c", 0.99) is False

    def test_or(self):
        assert evaluate("confidence < 0.2 or confidence > 0.8", "t", "c", 0.9) is True
        assert evaluate("confidence < 0.2 or confidence > 0.8", "t", "c", 0.5) is False

    def test_parentheses(self):
        cond = "( confidence > 0.9 or confidence < 0.1 ) and confidence != 0.95"
        assert evaluate(cond, "t", "c", 0.99) is True
        assert evaluate(cond, "t", "c", 0.5) is False

    def test_token_equality(self):
        assert evaluate('token == "secret"', "secret", "c", 1.0) is True
        assert evaluate('token != "secret"', "other", "c", 1.0) is True

    def test_context_equality(self):
        assert evaluate('context == "prod"', "tok", "prod", 1.0) is True
        assert evaluate('context == "prod"', "tok", "dev", 1.0) is False

    def test_token_string_ops(self):
        assert evaluate('token startswith "AB"', "ABC", "c", 1.0) is True
        assert evaluate('token endswith "C"', "ABC", "c", 1.0) is True
        assert evaluate('token contains "B"', "ABC", "c", 1.0) is True

    def test_population_condition(self):
        # 90210 (Beverly Hills) has population data in the bundled CSV.
        assert evaluate("population > 0", "90210", "c", 1.0) is True
        # Unknown zip -> condition fails.
        assert evaluate("population > 0", "00000", "c", 1.0) is False

    def test_unrecognized_raises(self):
        with pytest.raises(ValueError):
            evaluate("frobnicate > 3", "t", "c", 1.0)
