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

"""Tests for the catalog-driven action engine."""

import hashlib

import pytest

from phileas import actions
from phileas.actions.date_ops import shift_date, truncate_to_year
from phileas.policy.strategy import Strategy


def replace(config, filter_type, token):
    return Strategy.from_dict(config).get_replacement(filter_type, token)


class TestActions:
    def test_redact_default_format(self):
        assert replace({"strategy": "REDACT"}, "ssn", "123") == "{{{REDACTED-ssn}}}"

    def test_redact_custom_format(self):
        out = replace({"strategy": "REDACT", "redactionFormat": "[X-%t]"}, "email-address", "a@b.com")
        assert out == "[X-email-address]"

    def test_mask_default(self):
        assert replace({"strategy": "MASK"}, "ssn", "12345") == "*****"

    def test_mask_char_and_length(self):
        assert replace({"strategy": "MASK", "maskCharacter": "X"}, "ssn", "12345") == "XXXXX"
        assert replace({"strategy": "MASK", "maskCharacter": "X", "maskLength": 3}, "ssn", "12345") == "XXX"

    def test_mask_length_string(self):
        # The catalog types maskLength as a string: numeric string -> fixed length,
        # "SAME"/non-numeric -> full token length.
        assert replace({"strategy": "MASK", "maskCharacter": "X", "maskLength": "4"}, "ssn", "12345") == "XXXX"
        assert replace({"strategy": "MASK", "maskCharacter": "X", "maskLength": "SAME"}, "ssn", "12345") == "XXXXX"

    def test_static_replace(self):
        assert replace({"strategy": "STATIC_REPLACE", "staticReplacement": "[GONE]"}, "x", "y") == "[GONE]"

    def test_hash_sha256(self):
        out = replace({"strategy": "HASH_SHA256_REPLACE"}, "ssn", "123-45-6789")
        assert out == hashlib.sha256(b"123-45-6789").hexdigest()

    def test_last_4(self):
        assert replace({"strategy": "LAST_4"}, "cc", "4111111111111111") == "************1111"
        assert replace({"strategy": "LAST_4"}, "cc", "12") == "12"

    def test_truncate(self):
        assert replace({"strategy": "TRUNCATE"}, "x", "abcdefgh") == "abcd"

    def test_abbreviate(self):
        assert replace({"strategy": "ABBREVIATE"}, "name", "John Quincy Adams") == "JQA"

    def test_shift_date(self):
        assert replace({"strategy": "SHIFT", "shiftDays": 10}, "date", "01/05/2020") == "01/15/2020"

    def test_truncate_to_year(self):
        assert replace({"strategy": "TRUNCATE_TO_YEAR"}, "date", "01/05/2020") == "2020"

    def test_encrypt_marker(self):
        # ENCRYPT requires an externally configured key; the engine emits a marker.
        assert replace({"strategy": "CRYPTO_REPLACE"}, "ssn", "x") == "{{{ENCRYPTED-ssn}}}"

    def test_unknown_strategy_raises(self):
        with pytest.raises(ValueError):
            replace({"strategy": "NO_SUCH_STRATEGY"}, "x", "y")

    def test_is_known(self):
        assert actions.is_known("MASK") is True
        assert actions.is_known("HASH_SHA256_REPLACE") is True
        assert actions.is_known("BOGUS") is False


class TestDateOps:
    @pytest.mark.parametrize("token,expected", [
        ("01/05/2020", "2020"),
        ("2020-03-15", "2020"),
        ("January 15, 1990", "1990"),
        ("15 January 1990", "1990"),
    ])
    def test_truncate_to_year_formats(self, token, expected):
        assert truncate_to_year(token) == expected

    def test_truncate_to_year_unparseable(self):
        assert truncate_to_year("not a date") == "not a date"

    def test_shift_preserves_iso_format(self):
        assert shift_date("2020-01-05", 0, 0, 10) == "2020-01-15"

    def test_shift_month_rollover(self):
        assert shift_date("01/25/2020", 0, 0, 10) == "02/04/2020"

    def test_shift_unparseable_unchanged(self):
        assert shift_date("xyz", 1, 2, 3) == "xyz"
