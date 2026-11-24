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

"""Tests for the SHIFT strategy with shiftRandom (issue #128)."""

import re
import threading
import time
from datetime import date, timedelta

from phileas import FilterService
from phileas.actions import CONTEXT_SHIFT_KEY, get_replacement
from phileas.actions.date_ops import MIN_RANDOM_SHIFT_DAYS, _shift_value, random_shift_days
from phileas.policy.policy import Policy
from phileas.policy.strategy import Strategy
from phileas.services.context import AbstractContextService, InMemoryContextService

RANDOM = {"strategy": "SHIFT", "shiftRandom": True}
CONTEXT = {"strategy": "SHIFT", "shiftRandom": True, "replacementScope": "CONTEXT"}


def _iso_days(original: str, shifted: str) -> int:
    return (date.fromisoformat(shifted) - date.fromisoformat(original)).days


def _policy(strategy: dict) -> Policy:
    return Policy.from_dict({"name": "p", "identifiers": {"date": {"dateFilterStrategies": [strategy]}}})


def _numeric_days(original: str, shifted: str) -> int:
    def parse(value):
        month, day, year = (int(part) for part in value.split("/"))
        return date(year, month, day)

    return (parse(shifted) - parse(original)).days


def _java_shifts(dt: date) -> set:
    """Every shift, in days, that the Java engine's ranges can draw for *dt*."""
    shifts = set()
    for days in range(1, 30):
        for months in range(1, 12):
            for years in (1, 2):
                shifted = _shift_value(dt + timedelta(days=days), 0, months, 0)
                shifts.add((_shift_value(shifted, -years, 0, 0) - dt).days)
    return shifts


class TestRandomShift:
    def test_document_scope_never_returns_the_date(self):
        moves = [
            _iso_days("2021-02-28", get_replacement("SHIFT", RANDOM, "date", "2021-02-28"))
            for _ in range(1000)
        ]
        assert min(abs(move) for move in moves) >= MIN_RANDOM_SHIFT_DAYS

    def test_context_scope_never_returns_the_date(self):
        moves = []
        for _ in range(1000):
            replacement = Strategy(CONTEXT).get_replacement(
                "date", "2021-02-28", "ctx", context_service=InMemoryContextService()
            )
            moves.append(_iso_days("2021-02-28", replacement))
        assert min(abs(move) for move in moves) >= MIN_RANDOM_SHIFT_DAYS

    def test_draws_from_the_java_ranges(self):
        dt = date(2021, 2, 28)
        possible = _java_shifts(dt)
        # The ranges alone can leave this date where it is, which is why short draws are drawn again.
        assert 0 in possible
        drawn = {random_shift_days(dt) for _ in range(2000)}
        assert drawn <= {shift for shift in possible if abs(shift) >= MIN_RANDOM_SHIFT_DAYS}
        # One and two years back are both drawn.
        assert any(shift > -365 for shift in drawn) and any(shift < -400 for shift in drawn)

    def test_fixed_offsets_are_ignored(self):
        config = dict(RANDOM, shiftDays=10, shiftMonths=0, shiftYears=0)
        for _ in range(200):
            replacement = get_replacement("SHIFT", config, "date", "01/05/2020")
            assert abs(_numeric_days("01/05/2020", replacement)) >= MIN_RANDOM_SHIFT_DAYS

    def test_shift_random_as_a_string(self):
        replacement = get_replacement("SHIFT", dict(RANDOM, shiftRandom="true"), "date", "2021-02-28")
        assert abs(_iso_days("2021-02-28", replacement)) >= MIN_RANDOM_SHIFT_DAYS

    def test_shift_random_false_keeps_the_fixed_shift(self):
        config = {"strategy": "SHIFT", "shiftRandom": False, "shiftDays": 10}
        assert get_replacement("SHIFT", config, "date", "01/05/2020") == "01/15/2020"

    def test_keeps_the_date_format(self):
        assert re.fullmatch(r"\d{2}/\d{2}/\d{4}", get_replacement("SHIFT", RANDOM, "date", "01/05/2020"))
        named = get_replacement("SHIFT", RANDOM, "date", "January 5, 2020")
        assert re.fullmatch(r"[A-Z][a-z]+ \d{1,2}, \d{4}", named)

    def test_unreadable_date_is_redacted(self):
        assert get_replacement("SHIFT", RANDOM, "date", "02/31/2020") == "{{{REDACTED-date}}}"

    def test_unreadable_date_stores_no_context_shift(self):
        svc = InMemoryContextService()
        replacement = Strategy(CONTEXT).get_replacement("date", "02/31/2020", "ctx", context_service=svc)
        assert replacement == "{{{REDACTED-date}}}"
        assert svc.get("ctx", CONTEXT_SHIFT_KEY) is None

    def test_context_scope_without_a_context_service_shifts_each_date(self):
        replacement = get_replacement("SHIFT", CONTEXT, "date", "2021-02-28")
        assert abs(_iso_days("2021-02-28", replacement)) >= MIN_RANDOM_SHIFT_DAYS


class TestRandomShiftInFilterService:
    def test_issue_example_is_shifted_in_both_scopes(self):
        text = "Admitted 01/05/2020. Surgery 01/07/2020."
        for scope in ("DOCUMENT", "CONTEXT"):
            result = FilterService().filter(_policy(dict(RANDOM, replacementScope=scope)), "ctx", "doc", text)
            assert "01/05/2020" not in result.filtered_text
            assert "01/07/2020" not in result.filtered_text

    def test_document_scope_shifts_each_date_on_its_own(self):
        text = "Admitted 01/05/2020. Surgery 01/07/2020."
        gaps = set()
        for _ in range(20):
            result = FilterService().filter(_policy(RANDOM), "ctx", "doc", text)
            admitted, surgery = re.findall(r"\d{2}/\d{2}/\d{4}", result.filtered_text)
            gaps.add(_numeric_days(admitted, surgery))
        # Each date gets its own draw, so the 2 days between them do not survive every time.
        assert gaps != {2}

    def test_context_scope_moves_every_date_by_the_same_days(self):
        svc = InMemoryContextService()
        service = FilterService(svc)
        policy = _policy(CONTEXT)
        first = service.filter(policy, "patient-1", "doc-1", "Seen 01/30/2020 and 01/31/2020.")
        second = service.filter(policy, "patient-1", "doc-2", "Discharged 2020-03-15.")

        jan30, jan31 = re.findall(r"\d{2}/\d{2}/\d{4}", first.filtered_text)
        (discharged,) = re.findall(r"\d{4}-\d{2}-\d{2}", second.filtered_text)
        move = _numeric_days("01/30/2020", jan30)
        assert abs(move) >= MIN_RANDOM_SHIFT_DAYS
        # A day apart and in order, as before the shift.
        assert _numeric_days(jan30, jan31) == 1
        assert _iso_days("2020-03-15", discharged) == move
        # Stored once, as a number of days.
        assert svc.get("patient-1", CONTEXT_SHIFT_KEY) == str(move)

    def test_contexts_keep_their_own_shift(self):
        svc = InMemoryContextService()
        service = FilterService(svc)
        policy = _policy(CONTEXT)
        moves = set()
        for i in range(20):
            result = service.filter(policy, f"patient-{i}", "doc", "Seen 2021-02-28.")
            (shifted,) = re.findall(r"\d{4}-\d{2}-\d{2}", result.filtered_text)
            assert svc.get(f"patient-{i}", CONTEXT_SHIFT_KEY) == str(_iso_days("2021-02-28", shifted))
            moves.add(shifted)
        assert len(moves) > 1


class TestComputeValueIfAbsent:
    def test_in_memory_runs_the_supplier_once(self):
        svc = InMemoryContextService()
        calls = []

        def supplier():
            calls.append(1)
            time.sleep(0.01)
            return str(len(calls))

        results = []
        threads = [
            threading.Thread(
                target=lambda: results.append(svc.compute_value_if_absent("ctx", "key", supplier))
            )
            for _ in range(8)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert len(calls) == 1
        assert results == ["1"] * 8

    def test_in_memory_keeps_values_per_context(self):
        svc = InMemoryContextService()
        assert svc.compute_value_if_absent("a", "key", lambda: "1") == "1"
        assert svc.compute_value_if_absent("a", "key", lambda: "2") == "1"
        assert svc.compute_value_if_absent("b", "key", lambda: "3") == "3"

    def test_default_uses_get_and_put(self):
        class DictContextService(AbstractContextService):
            def __init__(self):
                self.data = {}

            def put(self, context, token, replacement):
                self.data[(context, token)] = replacement

            def get(self, context, token):
                return self.data.get((context, token))

            def contains(self, context, token):
                return (context, token) in self.data

        svc = DictContextService()
        assert svc.compute_value_if_absent("ctx", "key", lambda: "40") == "40"
        assert svc.compute_value_if_absent("ctx", "key", lambda: "50") == "40"
        assert svc.data == {("ctx", "key"): "40"}
