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

import pytest

from phileas import actions
from phileas.actions.date_ops import shift_date, truncate_to_year
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

    def test_unknown_type_passes_through(self):
        # No service registered for this filter type -> token returned unchanged.
        assert replace({"strategy": "RANDOM_REPLACE"}, "unknown-filter-type", "KEEPME") == "KEEPME"


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

    def test_shorter_than_4_unchanged(self):
        assert replace({"strategy": "LAST_4"}, "cc", "12") == "12"

    def test_exactly_4_unchanged(self):
        # len > 4 is required to mask; exactly 4 is returned as-is.
        assert replace({"strategy": "LAST_4"}, "cc", "1234") == "1234"


# --- TRUNCATE ----------------------------------------------------------------


class TestTruncate:
    def test_longer_than_4(self):
        assert replace({"strategy": "TRUNCATE"}, "x", "abcdefgh") == "abcd"

    def test_short_unchanged(self):
        assert replace({"strategy": "TRUNCATE"}, "x", "abc") == "abc"

    def test_exactly_4_unchanged(self):
        assert replace({"strategy": "TRUNCATE"}, "x", "abcd") == "abcd"


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

    def test_unparseable_passthrough(self):
        assert replace({"strategy": "SHIFT", "shiftDays": 5}, "date", "not-a-date") == "not-a-date"


# --- Markers / passthrough strategies ----------------------------------------


class TestMarkersAndPassthrough:
    def test_crypto_replace_marker(self):
        assert replace({"strategy": "CRYPTO_REPLACE"}, "ssn", "x") == "{{{ENCRYPTED-ssn}}}"

    def test_fpe_encrypt_replace_marker(self):
        assert replace({"strategy": "FPE_ENCRYPT_REPLACE"}, "ssn", "x") == "{{{FPE-ENCRYPTED-ssn}}}"

    def test_relative_passthrough(self):
        assert replace({"strategy": "RELATIVE"}, "date", "2020-01-05") == "2020-01-05"

    def test_truncate_to_year_strategy(self):
        assert replace({"strategy": "TRUNCATE_TO_YEAR"}, "date", "01/05/2020") == "2020"


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

    def test_unparseable_unchanged(self):
        assert shift_date("xyz", 1, 2, 3) == "xyz"


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

    def test_unparseable_passthrough(self):
        assert truncate_to_year("not a date") == "not a date"
