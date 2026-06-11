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

"""Deeper characterization tests for phileas.policy.conditions.evaluate."""

import pytest

from phileas.policy.conditions import evaluate
from phileas.policy.zip_code_population import get_population

# A zip code that is present in the bundled CSV.
KNOWN_ZIP = "90210"
KNOWN_ZIP_POP = get_population(KNOWN_ZIP)
# A zip code that is not present in the bundled CSV.
UNKNOWN_ZIP = "00000"


def test_known_zip_is_present_in_bundled_csv():
    assert KNOWN_ZIP_POP is not None
    assert get_population(UNKNOWN_ZIP) is None


class TestConfidenceComparisonOperators:
    @pytest.mark.parametrize(
        "condition,confidence,expected",
        [
            # greater than
            ("confidence > 0.5", 0.6, True),
            ("confidence > 0.5", 0.5, False),
            ("confidence > 0.5", 0.4, False),
            # greater than or equal
            ("confidence >= 0.5", 0.6, True),
            ("confidence >= 0.5", 0.5, True),
            ("confidence >= 0.5", 0.4, False),
            # less than
            ("confidence < 0.5", 0.4, True),
            ("confidence < 0.5", 0.5, False),
            ("confidence < 0.5", 0.6, False),
            # less than or equal
            ("confidence <= 0.5", 0.4, True),
            ("confidence <= 0.5", 0.5, True),
            ("confidence <= 0.5", 0.6, False),
            # equality (==)
            ("confidence == 0.5", 0.5, True),
            ("confidence == 0.5", 0.6, False),
            # equality (single =)
            ("confidence = 0.5", 0.5, True),
            ("confidence = 0.5", 0.6, False),
            # inequality
            ("confidence != 0.5", 0.6, True),
            ("confidence != 0.5", 0.5, False),
        ],
    )
    def test_confidence_operators(self, condition, confidence, expected):
        assert evaluate(condition, "tok", "ctx", confidence) is expected

    def test_integer_threshold_and_leading_dot(self):
        assert evaluate("confidence > 0", "t", "c", 0.5) is True
        assert evaluate("confidence < .9", "t", "c", 0.5) is True
        assert evaluate("confidence > .9", "t", "c", 0.5) is False


class TestTokenContextEquality:
    @pytest.mark.parametrize(
        "condition,token,context,expected",
        [
            ('token == "alice"', "alice", "ctx", True),
            ('token == "alice"', "bob", "ctx", False),
            ('token != "alice"', "bob", "ctx", True),
            ('token != "alice"', "alice", "ctx", False),
            ('context == "default"', "tok", "default", True),
            ('context == "default"', "tok", "other", False),
            ('context != "default"', "tok", "other", True),
            ('context != "default"', "tok", "default", False),
        ],
    )
    def test_equality(self, condition, token, context, expected):
        assert evaluate(condition, token, context, 0.5) is expected


class TestStringPredicates:
    @pytest.mark.parametrize(
        "condition,token,expected",
        [
            ('token startswith "ab"', "abcdef", True),
            ('token startswith "ab"', "xabcd", False),
            ('token endswith "ef"', "abcdef", True),
            ('token endswith "ef"', "abcdx", False),
            ('token contains "cd"', "abcdef", True),
            ('token contains "zz"', "abcdef", False),
        ],
    )
    def test_token_predicates(self, condition, token, expected):
        assert evaluate(condition, token, "ctx", 0.5) is expected

    @pytest.mark.parametrize(
        "condition,context,expected",
        [
            ('context startswith "de"', "default", True),
            ('context endswith "lt"', "default", True),
            ('context contains "fau"', "default", True),
            ('context contains "zzz"', "default", False),
        ],
    )
    def test_context_predicates(self, condition, context, expected):
        assert evaluate(condition, "tok", context, 0.5) is expected


class TestPopulation:
    def test_known_zip_greater_than(self):
        # 90210 population is well above 100.
        assert evaluate("population > 100", KNOWN_ZIP, "c", 0.5) is True

    def test_known_zip_greater_equal(self):
        assert evaluate(f"population >= {KNOWN_ZIP_POP}", KNOWN_ZIP, "c", 0.5) is True

    def test_known_zip_less_than_low_threshold(self):
        assert evaluate("population < 100", KNOWN_ZIP, "c", 0.5) is False

    def test_known_zip_less_than_high_threshold(self):
        assert evaluate("population < 100000000", KNOWN_ZIP, "c", 0.5) is True

    def test_known_zip_exact_population(self):
        assert evaluate(f"population == {KNOWN_ZIP_POP}", KNOWN_ZIP, "c", 0.5) is True

    @pytest.mark.parametrize("op", [">", ">=", "<", "<=", "==", "=", "!="])
    def test_unknown_zip_always_false(self, op):
        # An unknown zip yields population None, which evaluates to False
        # regardless of the operator.
        assert evaluate(f"population {op} 100", UNKNOWN_ZIP, "c", 0.5) is False


class TestBooleanComposition:
    def test_and_both_true(self):
        assert evaluate("confidence > 0.1 and confidence < 0.9", "t", "c", 0.5) is True

    def test_and_one_false(self):
        assert evaluate("confidence > 0.1 and confidence > 0.9", "t", "c", 0.5) is False

    def test_or_one_true(self):
        assert evaluate("confidence < 0.1 or confidence > 0.3", "t", "c", 0.5) is True

    def test_or_both_false(self):
        assert evaluate("confidence < 0.1 or confidence > 0.9", "t", "c", 0.5) is False

    def test_parentheses_group(self):
        # (F or T) and T  -> True
        cond = "(confidence < 0.1 or confidence > 0.3) and confidence < 0.9"
        assert evaluate(cond, "t", "c", 0.5) is True

    def test_parentheses_change_grouping(self):
        # F and (T or T)  -> False because the leading factor is False
        cond = "confidence > 0.9 and (confidence > 0.1 or confidence < 0.8)"
        assert evaluate(cond, "t", "c", 0.5) is False

    def test_nested_parentheses(self):
        cond = "((confidence > 0.1) and (confidence < 0.9))"
        assert evaluate(cond, "t", "c", 0.5) is True

    def test_mixed_token_and_confidence(self):
        cond = 'token == "ssn" and confidence > 0.8'
        assert evaluate(cond, "ssn", "c", 0.9) is True
        assert evaluate(cond, "ssn", "c", 0.5) is False
        assert evaluate(cond, "name", "c", 0.9) is False


class TestPrecedence:
    def test_and_binds_tighter_than_or_left(self):
        # T or (F and F) == True
        cond = "confidence > 0.5 or confidence > 0.9 and confidence < 0.1"
        assert evaluate(cond, "t", "c", 0.6) is True

    def test_and_binds_tighter_than_or_right(self):
        # F or (T and T) == True
        cond = "confidence < 0.1 or confidence > 0.9 and confidence > 0.5"
        assert evaluate(cond, "t", "c", 0.95) is True

    def test_and_binds_tighter_than_or_trailing_leaf(self):
        # (F and ?) or T == True
        cond = "confidence < 0.1 and confidence > 0.05 or confidence == 0.6"
        assert evaluate(cond, "t", "c", 0.6) is True

    def test_or_short_circuit_semantics_value(self):
        # F or F == False; ensures the or branch is genuinely combined.
        cond = "confidence < 0.1 or confidence > 0.9 and confidence > 0.95"
        assert evaluate(cond, "t", "c", 0.5) is False


class TestWhitespaceVariations:
    @pytest.mark.parametrize(
        "condition",
        [
            "confidence>0.4",
            "confidence > 0.4",
            "confidence  >  0.4",
            "  confidence > 0.4  ",
            "confidence\t>\t0.4",
        ],
    )
    def test_confidence_whitespace(self, condition):
        assert evaluate(condition, "t", "c", 0.5) is True

    def test_token_equality_no_spaces_around_op(self):
        assert evaluate('token=="x"', "x", "c", 0.5) is True
        assert evaluate('token  ==  "x"', "x", "c", 0.5) is True

    def test_extra_spaces_around_and(self):
        assert (
            evaluate("confidence > 0.1   and   confidence < 0.9", "t", "c", 0.5)
            is True
        )


class TestQuotedValues:
    def test_quoted_value_with_spaces(self):
        assert evaluate('token == "John Smith"', "John Smith", "c", 0.5) is True
        assert evaluate('token == "John Smith"', "John", "c", 0.5) is False

    def test_quoted_value_containing_word_and(self):
        # The word "and" inside quotes must not be parsed as a boolean operator.
        assert evaluate('token == "cats and dogs"', "cats and dogs", "c", 0.5) is True
        assert evaluate('token != "cats and dogs"', "cats", "c", 0.5) is True

    def test_quoted_value_containing_word_or(self):
        assert evaluate('token == "a or b"', "a or b", "c", 0.5) is True
        assert evaluate('token == "a or b"', "a", "c", 0.5) is False

    def test_quoted_contains_with_and_word(self):
        assert evaluate('token contains "x and y"', "z x and y z", "c", 0.5) is True

    def test_quoted_and_then_real_operator(self):
        cond = 'token == "a and b" and confidence > 0.5'
        assert evaluate(cond, "a and b", "c", 0.9) is True
        assert evaluate(cond, "a and b", "c", 0.1) is False


class TestEmptyAndErrors:
    @pytest.mark.parametrize("condition", ["", "   ", "\t", "\n", "  \t \n "])
    def test_empty_or_whitespace_is_true(self, condition):
        assert evaluate(condition, "t", "c", 0.5) is True

    def test_unrecognized_leaf_raises_value_error(self):
        with pytest.raises(ValueError):
            evaluate("bogus > 5", "t", "c", 0.5)

    def test_unknown_field_raises_value_error(self):
        with pytest.raises(ValueError):
            evaluate('foo == "bar"', "t", "c", 0.5)

    def test_unrecognized_leaf_inside_boolean_raises(self):
        with pytest.raises(ValueError):
            evaluate("confidence > 0.1 and totally_invalid", "t", "c", 0.5)
