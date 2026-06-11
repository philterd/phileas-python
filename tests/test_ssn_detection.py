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

"""Characterization tests for :class:`SSNFilter` detection."""

import pytest

from phileas.filters.ssn_filter import SSNFilter


def _texts(spans):
    return [s.text for s in spans]


class TestSSNPositive:
    def test_formatted_ssn_detected(self):
        spans = SSNFilter().detect("SSN 123-45-6789.")
        assert len(spans) == 1
        span = spans[0]
        assert span.text == "123-45-6789"
        assert span.filter_type == "ssn"
        assert span.confidence == 1.0
        assert span.replacement == ""
        assert span.character_start == 4
        assert span.character_end == 15

    def test_unformatted_ssn_detected(self):
        spans = SSNFilter().detect("123456789")
        assert len(spans) == 1
        span = spans[0]
        assert span.text == "123456789"
        assert span.filter_type == "ssn"
        assert span.character_start == 0
        assert span.character_end == 9

    def test_formatted_ssn_offsets_in_sentence(self):
        text = "My number is 123-45-6789 ok"
        spans = SSNFilter().detect(text)
        assert len(spans) == 1
        span = spans[0]
        assert span.character_start == 13
        assert span.character_end == 24
        assert text[span.character_start:span.character_end] == "123-45-6789"

    @pytest.mark.parametrize(
        "value",
        [
            "123-45-6789",
            "567-89-1234",
            "078-05-1121",  # leading-zero area, valid (not the blocked 078-05-1120)
            "219-09-9998",  # one off from the blocked 219-09-9999
        ],
    )
    def test_valid_formatted_values(self, value):
        spans = SSNFilter().detect(value)
        assert _texts(spans) == [value]

    @pytest.mark.parametrize(
        "value",
        [
            "123456789",
            "567891234",
            "078051121",
            "219099998",
        ],
    )
    def test_valid_unformatted_values(self, value):
        spans = SSNFilter().detect(value)
        assert value in _texts(spans)

    def test_filter_type_is_ssn(self):
        spans = SSNFilter().detect("123-45-6789")
        assert all(s.filter_type == "ssn" for s in spans)

    def test_default_config_construction(self):
        # No config supplied -> defaults to {}; still detects.
        f = SSNFilter()
        assert f.config == {}
        assert _texts(f.detect("123-45-6789")) == ["123-45-6789"]


class TestSSNNegativeArea:
    @pytest.mark.parametrize(
        "value",
        [
            "000-12-3456",  # area 000
            "666-12-3456",  # area 666
            "900-12-3456",  # area 9xx
            "999-12-3456",  # area 9xx
            "987-65-4321",  # area 9xx
        ],
    )
    def test_invalid_area_formatted_not_detected(self, value):
        assert SSNFilter().detect(value) == []

    @pytest.mark.parametrize(
        "value",
        [
            "000123456",
            "666123456",
            "900123456",
            "999123456",
            "987654321",
        ],
    )
    def test_invalid_area_unformatted_not_detected(self, value):
        assert SSNFilter().detect(value) == []


class TestSSNNegativeGroupAndSerial:
    def test_group_00_formatted_not_detected(self):
        assert SSNFilter().detect("123-00-6789") == []

    def test_group_00_unformatted_not_detected(self):
        assert SSNFilter().detect("123006789") == []

    def test_serial_0000_formatted_not_detected(self):
        assert SSNFilter().detect("123-45-0000") == []

    def test_serial_0000_unformatted_not_detected(self):
        assert SSNFilter().detect("123450000") == []


class TestSSNKnownInvalid:
    @pytest.mark.parametrize("value", ["219-09-9999", "078-05-1120"])
    def test_known_invalid_formatted_not_detected(self, value):
        assert SSNFilter().detect(value) == []

    @pytest.mark.parametrize("value", ["219099999", "078051120"])
    def test_known_invalid_unformatted_not_detected(self, value):
        assert SSNFilter().detect(value) == []


class TestSSNBoundaries:
    def test_ten_digit_number_not_detected(self):
        # No word boundary around a valid 9-digit run.
        assert SSNFilter().detect("1234567890") == []

    def test_digits_embedded_in_letters_not_detected(self):
        assert SSNFilter().detect("a123456789b") == []

    def test_phone_like_not_detected(self):
        assert SSNFilter().detect("Call 800-555-1234") == []

    def test_empty_text_returns_no_spans(self):
        assert SSNFilter().detect("") == []

    def test_no_ssn_returns_no_spans(self):
        assert SSNFilter().detect("there is nothing here") == []

    def test_only_first_of_two_valid_formatted_detected(self):
        # The second value 987-65-4321 has an invalid 9xx area, so only the
        # first formatted SSN is detected.
        spans = SSNFilter().detect("123-45-6789 and 987-65-4321")
        assert _texts(spans) == ["123-45-6789"]

    def test_two_valid_formatted_both_detected(self):
        spans = SSNFilter().detect("123-45-6789 and 567-89-1234")
        assert sorted(_texts(spans)) == ["123-45-6789", "567-89-1234"]
