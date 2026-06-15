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

"""Tests for the identifier-filter ``validator`` field, dispatch, and registry."""

import pytest

from phileas.filters import validators as V
from phileas.filters.validators import resolve_validator
from phileas.filters.pattern_filter import PatternFilter


@pytest.fixture
def even_validator():
    """Registers a throwaway validator that keeps even-numbered tokens."""
    captured = {}

    def factory(params):
        captured["params"] = params
        return lambda text: text.isdigit() and int(text) % 2 == 0

    V.register_validator("test-even", factory)
    try:
        yield captured
    finally:
        V._VALIDATORS.pop("test-even", None)


class TestResolve:
    def test_absent_validator_is_none(self):
        # No validator declared means keep every match.
        assert resolve_validator(None) is None

    def test_string_form_resolves(self, even_validator):
        predicate = resolve_validator("test-even")
        assert callable(predicate)
        assert even_validator["params"] is None
        assert predicate("4") is True
        assert predicate("5") is False

    def test_object_form_resolves_with_params(self, even_validator):
        predicate = resolve_validator({"name": "test-even", "params": {"k": "v"}})
        assert callable(predicate)
        assert even_validator["params"] == {"k": "v"}

    def test_object_form_without_params(self, even_validator):
        predicate = resolve_validator({"name": "test-even"})
        assert callable(predicate)
        assert even_validator["params"] is None

    def test_unknown_name_string_raises(self):
        with pytest.raises(ValueError, match="Unsupported identifier validator 'does-not-exist'"):
            resolve_validator("does-not-exist")

    def test_unknown_name_object_raises(self):
        with pytest.raises(ValueError, match="Unsupported identifier validator"):
            resolve_validator({"name": "does-not-exist"})

    def test_empty_name_raises(self):
        with pytest.raises(ValueError, match="non-empty name"):
            resolve_validator({"name": ""})

    def test_invalid_type_raises(self):
        with pytest.raises(ValueError, match="string or an object"):
            resolve_validator(123)


class TestPatternFilterDispatch:
    def test_validator_keeps_passing_match(self, even_validator):
        f = PatternFilter(
            {"classification": "num", "pattern": r"\b\d+\b", "validator": "test-even"}
        )
        spans = f.detect("values 4 and 5 here")
        assert [s.text for s in spans] == ["4"]

    def test_validator_drops_all_failing(self, even_validator):
        f = PatternFilter(
            {"classification": "num", "pattern": r"\b\d+\b", "validator": "test-even"}
        )
        assert f.detect("values 3 and 7 here") == []

    def test_object_form_through_filter(self, even_validator):
        f = PatternFilter(
            {
                "classification": "num",
                "pattern": r"\b\d+\b",
                "validator": {"name": "test-even", "params": {}},
            }
        )
        assert [s.text for s in f.detect("8 9 10")] == ["8", "10"]

    def test_no_validator_keeps_every_match(self):
        f = PatternFilter({"classification": "num", "pattern": r"\b\d+\b"})
        assert [s.text for s in f.detect("3 and 4")] == ["3", "4"]

    def test_unknown_validator_raises_at_construction(self):
        with pytest.raises(ValueError, match="Unsupported identifier validator"):
            PatternFilter(
                {"classification": "num", "pattern": r"\d+", "validator": "does-not-exist"}
            )
