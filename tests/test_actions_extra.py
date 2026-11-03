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

"""Deeper characterization tests for the catalog-driven action engine.

These exercise every ``phileas_enum`` reachable through
``Strategy(config).get_replacement(filter_type, token)`` plus the
``phileas.actions.date_ops`` helpers directly.
"""

import hashlib
from datetime import date

import pytest

from phileas import actions
from phileas.actions.date_ops import _period, relative_date, shift_date, truncate_to_year
from phileas.policy.strategy import Strategy


def replace(config, filter_type, token):
    return Strategy.from_dict(config).get_replacement(filter_type, token)


# --- REDACT ------------------------------------------------------------------


class TestRedact:
    def test_default_format(self):
        assert replace({"strategy": "REDACT"}, "ssn", "123-45-6789") == "{{{REDACTED-ssn}}}"

    def test_empty_config_defaults_to_redact(self):
        # Strategy(None) defaults to a REDACT strategy.
        assert Strategy().get_replacement("phone-number", "555") == "{{{REDACTED-phone-number}}}"

    def test_custom_format_with_substitution(self):
        out = replace({"strategy": "REDACT", "redactionFormat": "<<%t>>"}, "email-address", "a@b.com")
        assert out == "<<email-address>>"

    def test_custom_format_without_placeholder(self):
        out = replace({"strategy": "REDACT", "redactionFormat": "GONE"}, "ssn", "x")
        assert out == "GONE"

    def test_empty_format_falls_back_to_default(self):
        # A falsy redactionFormat is treated as unset and falls back.
        out = replace({"strategy": "REDACT", "redactionFormat": ""}, "ssn", "x")
        assert out == "{{{REDACTED-ssn}}}"


# --- MASK --------------------------------------------------------------------


class TestMask:
    def test_default_char_matches_token_length(self):
        assert replace({"strategy": "MASK"}, "ssn", "12345") == "*****"

    def test_custom_mask_character(self):
        assert replace({"strategy": "MASK", "maskCharacter": "X"}, "ssn", "12345") == "XXXXX"

    def test_mask_length_shorter_than_token(self):
        assert replace({"strategy": "MASK", "maskCharacter": "X", "maskLength": 3}, "ssn", "12345") == "XXX"

    def test_mask_length_longer_than_token(self):
        assert replace({"strategy": "MASK", "maskLength": 8}, "ssn", "12") == "********"

    def test_empty_token_default_length_zero(self):
        assert replace({"strategy": "MASK"}, "ssn", "") == ""

    def test_empty_token_with_custom_char(self):
        assert replace({"strategy": "MASK", "maskCharacter": "#"}, "ssn", "") == ""


# --- STATIC_REPLACE ----------------------------------------------------------


class TestStaticReplace:
    def test_value_set(self):
        assert replace({"strategy": "STATIC_REPLACE", "staticReplacement": "[GONE]"}, "x", "y") == "[GONE]"

    def test_value_missing_returns_empty(self):
        assert replace({"strategy": "STATIC_REPLACE"}, "x", "y") == ""


# --- RANDOM_REPLACE ----------------------------------------------------------


class TestRandomReplace:
    def test_known_type_changes_value_and_keeps_shape(self):
        # zip-code has an anonymization service; output differs but stays a 5-digit zip.
        outs = {replace({"strategy": "RANDOM_REPLACE"}, "zip-code", "90210") for _ in range(25)}
        assert "90210" not in outs
        assert all(len(o) == 5 and o.isdigit() for o in outs)

    def test_unknown_type_redacts(self):
        # No service registered for this filter type -> redacted, never left as-is.
        out = replace({"strategy": "RANDOM_REPLACE"}, "unknown-filter-type", "KEEPME")
        assert out == "{{{REDACTED-unknown-filter-type}}}"


# --- HASH_SHA256_REPLACE -----------------------------------------------------


class TestHashSha256:
    def test_matches_hashlib(self):
        out = replace({"strategy": "HASH_SHA256_REPLACE"}, "ssn", "123-45-6789")
        assert out == hashlib.sha256(b"123-45-6789").hexdigest()

    def test_deterministic(self):
        a = replace({"strategy": "HASH_SHA256_REPLACE"}, "ssn", "abc")
        b = replace({"strategy": "HASH_SHA256_REPLACE"}, "ssn", "abc")
        assert a == b
        assert len(a) == 64


# --- LAST_4 ------------------------------------------------------------------


class TestLast4:
    def test_longer_than_4(self):
        assert replace({"strategy": "LAST_4"}, "cc", "4111111111111111") == "************1111"

    def test_shorter_than_4_redacted(self):
        assert replace({"strategy": "LAST_4"}, "cc", "12") == "{{{REDACTED-cc}}}"

    def test_exactly_4_redacted(self):
        # The last four would be the whole value, so it is redacted.
        assert replace({"strategy": "LAST_4"}, "cc", "1234") == "{{{REDACTED-cc}}}"


# --- TRUNCATE ----------------------------------------------------------------


class TestTruncate:
    def test_longer_than_4(self):
        assert replace({"strategy": "TRUNCATE"}, "x", "abcdefgh") == "abcd"

    def test_short_redacted(self):
        assert replace({"strategy": "TRUNCATE"}, "x", "abc") == "{{{REDACTED-x}}}"

    def test_exactly_4_redacted(self):
        assert replace({"strategy": "TRUNCATE"}, "x", "abcd") == "{{{REDACTED-x}}}"


# --- ABBREVIATE --------------------------------------------------------------


class TestAbbreviate:
    def test_multi_word(self):
        assert replace({"strategy": "ABBREVIATE"}, "name", "John Quincy Adams") == "JQA"

    def test_single_word(self):
        assert replace({"strategy": "ABBREVIATE"}, "name", "Madonna") == "M"

    def test_empty_token(self):
        assert replace({"strategy": "ABBREVIATE"}, "name", "") == ""

    def test_extra_spaces_collapsed(self):
        assert replace({"strategy": "ABBREVIATE"}, "name", "  John   Adams  ") == "JA"


# --- SHIFT (through Strategy) -------------------------------------------------


class TestShiftStrategy:
    def test_shift_days(self):
        assert replace({"strategy": "SHIFT", "shiftDays": 10}, "date", "01/05/2020") == "01/15/2020"

    def test_shift_months(self):
        assert replace({"strategy": "SHIFT", "shiftMonths": 2}, "date", "01/05/2020") == "03/05/2020"

    def test_shift_years(self):
        assert replace({"strategy": "SHIFT", "shiftYears": 3}, "date", "01/05/2020") == "01/05/2023"

    def test_unparseable_redacted(self):
        assert replace({"strategy": "SHIFT", "shiftDays": 5}, "date", "not-a-date") == "{{{REDACTED-date}}}"

    def test_invalid_calendar_date_redacted(self):
        assert replace({"strategy": "SHIFT", "shiftDays": 5}, "date", "02/31/2020") == "{{{REDACTED-date}}}"

    def test_unparseable_uses_redaction_format(self):
        config = {"strategy": "SHIFT", "shiftDays": 5, "redactionFormat": "[%t]"}
        assert replace(config, "date", "not-a-date") == "[date]"


# --- Markers ------------------------------------------------------------------


class TestMarkers:
    def test_crypto_replace_marker(self):
        assert replace({"strategy": "CRYPTO_REPLACE"}, "ssn", "x") == "{{{ENCRYPTED-ssn}}}"

    def test_fpe_encrypt_replace_marker(self):
        assert replace({"strategy": "FPE_ENCRYPT_REPLACE"}, "ssn", "x") == "{{{FPE-ENCRYPTED-ssn}}}"

    def test_truncate_to_year_strategy(self):
        assert replace({"strategy": "TRUNCATE_TO_YEAR"}, "date", "01/05/2020") == "2020"


# --- RELATIVE ----------------------------------------------------------------


TODAY = date(2026, 11, 3)


@pytest.fixture
def fixed_today(monkeypatch):
    monkeypatch.setattr(actions, "_today", lambda: TODAY)


class TestRelativeStrategy:
    def test_past_date_months(self, fixed_today):
        assert replace({"strategy": "RELATIVE"}, "date", "2026-08-01") == "3 months ago"

    def test_past_date_years_and_months(self, fixed_today):
        assert replace({"strategy": "RELATIVE"}, "date", "01/05/2020") == "6 years 10 months ago"

    def test_other_formats(self, fixed_today):
        assert replace({"strategy": "RELATIVE"}, "date", "March 3, 2026") == "8 months ago"
        assert replace({"strategy": "RELATIVE"}, "date", "3 March 2026") == "8 months ago"

    def test_today(self, fixed_today):
        assert replace({"strategy": "RELATIVE"}, "date", "2026-11-03") == "0 months ago"

    def test_future_date_redacted_by_default(self, fixed_today):
        assert replace({"strategy": "RELATIVE"}, "date", "2027-02-03") == "{{{REDACTED-date}}}"

    @pytest.mark.parametrize("flag", [True, "true", "TRUE"])
    def test_future_date_allowed(self, fixed_today, flag):
        config = {"strategy": "RELATIVE", "futureDates": flag}
        assert replace(config, "date", "2027-02-03") == "in 3 months"

    def test_future_dates_false(self, fixed_today):
        config = {"strategy": "RELATIVE", "futureDates": False}
        assert replace(config, "date", "2027-02-03") == "{{{REDACTED-date}}}"

    def test_unparseable_redacted(self, fixed_today):
        assert replace({"strategy": "RELATIVE"}, "date", "not-a-date") == "{{{REDACTED-date}}}"

    def test_invalid_calendar_date_redacted(self, fixed_today):
        assert replace({"strategy": "RELATIVE"}, "date", "02/31/2020") == "{{{REDACTED-date}}}"

    def test_unparseable_uses_redaction_format(self, fixed_today):
        config = {"strategy": "RELATIVE", "redactionFormat": "[%t]"}
        assert replace(config, "date", "not-a-date") == "[date]"

    def test_uses_current_date_by_default(self):
        out = replace({"strategy": "RELATIVE"}, "date", "01/05/2020")
        assert out.endswith(" ago")
        assert "2020" not in out


class TestRelativeDate:
    def test_half_month_rounds_up(self):
        # 2 months 15 days.
        assert relative_date("2026-08-19", TODAY, False) == "3 months ago"

    def test_under_half_month_rounds_down(self):
        # 2 months 14 days.
        assert relative_date("2026-08-20", TODAY, False) == "2 months ago"

    def test_day_borrow_matches_java_period(self):
        # Period.between(2026-01-31, 2026-03-01) is 1 month 1 day.
        assert relative_date("2026-01-31", date(2026, 3, 1), False) == "1 months ago"

    def test_future(self):
        assert relative_date("2028-01-03", TODAY, True) == "in 1 years 2 months"

    def test_future_does_not_round(self):
        # Java's Period.between(date, now) is negative here, so days never reach 15.
        assert relative_date("2027-02-20", TODAY, True) == "in 3 months"
        assert relative_date("2026-12-01", TODAY, True) == "in 0 months"

    def test_period_matches_java_negative_normalization(self):
        # Period.between(2026-12-01, 2026-11-03) is -28 days.
        assert _period(date(2026, 12, 1), TODAY) == (0, 0, -28)
        # Period.between(2028-01-03, 2026-11-03) is -1 years -2 months.
        assert _period(date(2028, 1, 3), TODAY) == (-1, -2, 0)

    def test_future_not_allowed(self):
        assert relative_date("2028-01-03", TODAY, False) is None

    def test_unparseable(self):
        assert relative_date("xyz", TODAY, True) is None


# --- No strategy leaves the value in place -----------------------------------


class TestNeverReturnsToken:
    @pytest.mark.parametrize("config,filter_type,token", [
        ({"strategy": "RANDOM_REPLACE"}, "unknown-filter-type", "KEEPME"),
        ({"strategy": "LAST_4"}, "cc", "1234"),
        ({"strategy": "TRUNCATE"}, "x", "abcd"),
        ({"strategy": "TRUNCATE_TO_YEAR"}, "date", "not-a-date"),
        ({"strategy": "SHIFT", "shiftDays": 1}, "date", "not-a-date"),
        ({"strategy": "RELATIVE"}, "date", "not-a-date"),
        ({"strategy": "RELATIVE"}, "date", "2999-01-01"),
    ])
    def test_unappliable_value_is_redacted(self, config, filter_type, token):
        out = replace(config, filter_type, token)
        assert out != token
        assert out == f"{{{{{{REDACTED-{filter_type}}}}}}}"


# --- Engine introspection ----------------------------------------------------


class TestEngine:
    @pytest.mark.parametrize("enum", [
        "REDACT", "MASK", "RANDOM_REPLACE", "STATIC_REPLACE", "CRYPTO_REPLACE",
        "FPE_ENCRYPT_REPLACE", "HASH_SHA256_REPLACE", "LAST_4", "TRUNCATE",
        "TRUNCATE_TO_YEAR", "SHIFT", "RELATIVE", "ABBREVIATE",
    ])
    def test_is_known_true(self, enum):
        assert actions.is_known(enum) is True

    def test_is_known_false(self):
        assert actions.is_known("BOGUS") is False
        assert actions.is_known("") is False

    def test_unknown_enum_raises(self):
        with pytest.raises(ValueError):
            replace({"strategy": "NO_SUCH_STRATEGY"}, "x", "y")

    def test_get_replacement_unknown_enum_raises(self):
        with pytest.raises(ValueError):
            actions.get_replacement("NOPE", {}, "x", "y")


# --- date_ops.shift_date directly --------------------------------------------


class TestShiftDate:
    def test_days_iso_format_preserved(self):
        assert shift_date("2020-01-05", 0, 0, 10) == "2020-01-15"

    def test_days_slashed_format_preserved(self):
        assert shift_date("01/05/2020", 0, 0, 10) == "01/15/2020"

    def test_month_rollover(self):
        assert shift_date("06/15/2020", 0, 8, 0) == "02/15/2021"

    def test_month_rollover_to_december(self):
        assert shift_date("01/15/2020", 0, 11, 0) == "12/15/2020"

    def test_year_rollover_via_days(self):
        assert shift_date("12/25/2020", 0, 0, 10) == "01/04/2021"

    def test_year_shift(self):
        assert shift_date("01/05/2020", 3, 0, 0) == "01/05/2023"

    def test_leap_year_feb29_plus_one_day(self):
        assert shift_date("02/29/2020", 0, 0, 1) == "03/01/2020"

    def test_leap_year_feb29_clamped_into_non_leap(self):
        # Shifting Feb 29 (2020) by one year lands on non-leap 2021; day clamps to 28.
        assert shift_date("02/29/2020", 1, 0, 0) == "02/28/2021"

    def test_month_name_format_with_comma_preserved(self):
        assert shift_date("January 15, 1990", 0, 1, 0) == "February 15, 1990"

    def test_month_name_format_without_comma_preserved(self):
        assert shift_date("January 15 1990", 0, 0, 1) == "January 16 1990"

    def test_day_month_year_format_preserved(self):
        assert shift_date("15 January 1990", 0, 0, 5) == "20 January 1990"

    def test_unparseable_none(self):
        assert shift_date("xyz", 1, 2, 3) is None


# --- date_ops.truncate_to_year directly --------------------------------------


class TestTruncateToYear:
    @pytest.mark.parametrize("token,expected", [
        ("01/05/2020", "2020"),
        ("01-05-2020", "2020"),
        ("2020-03-15", "2020"),
        ("January 15, 1990", "1990"),
        ("15 January 1990", "1990"),
    ])
    def test_supported_formats(self, token, expected):
        assert truncate_to_year(token) == expected

    def test_unparseable_none(self):
        assert truncate_to_year("not a date") is None

    def test_invalid_calendar_date_none(self):
        assert truncate_to_year("02/31/2020") is None
