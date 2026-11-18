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

"""Characterization tests for DateFilter detection."""

import pytest

from phileas.filters.date_filter import DateFilter


@pytest.fixture
def date_filter():
    return DateFilter()


def _texts(spans):
    return [s.text for s in spans]


class TestConstruction:
    def test_default_config_is_empty_dict(self):
        assert DateFilter().config == {}

    def test_none_config_becomes_empty_dict(self):
        assert DateFilter(None).config == {}

    def test_filter_type_attribute(self):
        assert DateFilter().filter_type == "date"


class TestPositiveDetections:
    @pytest.mark.parametrize(
        "text,expected",
        [
            # MM/DD/YYYY
            ("01/15/1990", "01/15/1990"),
            ("1/15/1990", "1/15/1990"),
            ("12/25/2020", "12/25/2020"),
            ("5/9/2021", "5/9/2021"),
            ("01/15/2099", "01/15/2099"),
            # MM-DD-YYYY
            ("01-15-1990", "01-15-1990"),
            ("12-25-2020", "12-25-2020"),
            # ISO YYYY-MM-DD
            ("1990-01-15", "1990-01-15"),
            ("2020-12-31", "2020-12-31"),
            ("2099-12-31", "2099-12-31"),
            # Month DD, YYYY
            ("January 15, 1990", "January 15, 1990"),
            ("December 31, 2020", "December 31, 2020"),
            ("MARCH 5, 2020", "MARCH 5, 2020"),
            # Month DD YYYY (no comma)
            ("January 15 1990", "January 15 1990"),
            # DD Month YYYY
            ("15 January 1990", "15 January 1990"),
            ("15 january 1990", "15 january 1990"),
            ("3 January 2000", "3 January 2000"),
            ("5 MARCH 2020", "5 MARCH 2020"),
        ],
    )
    def test_detects_expected_text(self, date_filter, text, expected):
        assert expected in _texts(date_filter.detect(text))

    @pytest.mark.parametrize(
        "text,expected",
        [
            ("The date is 12/25/2020.", "12/25/2020"),
            ("born on 15 March 2005", "15 March 2005"),
            ("Event: 1990-01-15 (closed)", "1990-01-15"),
            ("Meeting on January 15, 1990 downtown", "January 15, 1990"),
        ],
    )
    def test_detects_embedded_date(self, date_filter, text, expected):
        assert expected in _texts(date_filter.detect(text))


class TestSpanAttributes:
    def test_filter_type_is_date(self, date_filter):
        spans = date_filter.detect("01/15/1990")
        assert spans
        assert all(s.filter_type == "date" for s in spans)

    def test_confidence_is_one(self, date_filter):
        spans = date_filter.detect("1990-01-15")
        assert spans
        assert all(s.confidence == 1.0 for s in spans)

    def test_replacement_always_empty(self, date_filter):
        spans = date_filter.detect("January 15, 1990")
        assert spans
        assert all(s.replacement == "" for s in spans)

    def test_offsets_match_source_text(self, date_filter):
        text = "The date is 12/25/2020."
        span = date_filter.detect(text)[0]
        assert text[span.character_start:span.character_end] == span.text

    def test_character_start_of_embedded_match(self, date_filter):
        text = "born on 15 March 2005"
        span = date_filter.detect(text)[0]
        assert span.character_start == text.index("15")
        assert span.text == "15 March 2005"

    def test_context_argument_does_not_error(self, date_filter):
        spans = date_filter.detect("01/15/1990", context="custom")
        assert spans
        assert spans[0].text == "01/15/1990"


class TestNegativeDetections:
    @pytest.mark.parametrize(
        "text",
        [
            # Invalid month (00 or 13)
            "13/15/1990",
            "00/15/1990",
            "2020-00-15",
            "2020-13-15",
            # Invalid day (32, 00)
            "01/32/1990",
            "2020-12-00",
            "2020-12-32",
            "32 January 1990",
            # ISO requires zero-padded month/day
            "2020-1-1",
            # Wrong separators / ordering
            "15-01-1990",
            "1990/01/15",
            # Two-digit year not supported
            "01/15/90",
            # Years outside 19xx/20xx
            "1899-01-01",
            "1800-01-01",
            "2100-01-01",
            # Non-dates
            "no date here",
            "random 12345",
            "the number is 42",
            "",
        ],
    )
    def test_no_detection(self, date_filter, text):
        assert date_filter.detect(text) == []


_ABBREVIATIONS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Sept", "Oct", "Nov", "Dec"]

_ABBREVIATED_FORMS = [
    "{m} {d}, {y}",
    "{m} {d} {y}",
    "{m}. {d}, {y}",
    "{m}. {d} {y}",
    "{d} {m} {y}",
    "{d} {m}. {y}",
]


class TestAbbreviatedMonths:
    """Months abbreviated to three letters, or Sept, in each form a spelled-out month is detected in."""

    @pytest.mark.parametrize("month", _ABBREVIATIONS)
    @pytest.mark.parametrize("form", _ABBREVIATED_FORMS)
    @pytest.mark.parametrize("day,year", [("5", "1950"), ("27", "2020"), ("09", "1969"), ("31", "1971")])
    def test_detected_whole(self, date_filter, month, form, day, year):
        date = form.format(m=month, d=day, y=year)
        assert _texts(date_filter.detect(f"It was on {date} at the office.")) == [date]

    @pytest.mark.parametrize("month", _ABBREVIATIONS)
    @pytest.mark.parametrize("case", [str.upper, str.lower])
    def test_any_case(self, date_filter, month, case):
        for date in (f"{case(month)} 5, 2020", f"5 {case(month)} 2020", f"{case(month)}. 5, 2020"):
            assert _texts(date_filter.detect(f"On {date} we met.")) == [date]

    @pytest.mark.parametrize(
        "text",
        [
            "Marble 10, 2020",
            "Junior 5 1990",
            "Decimal 3, 2000",
            "Septic 10, 2020",
            "Septuagint 3 2020",
            "Mayor 5, 2020",
            "Decal 3 2000",
            "10 Marble 2020",
            "10 Septic 2020",
        ],
    )
    def test_word_starting_with_an_abbreviation_is_not_a_month(self, date_filter, text):
        assert date_filter.detect(text) == []

    @pytest.mark.parametrize("text", ["Sep 2020", "September 2020", "Mar. 1965"])
    def test_month_and_year_without_a_day_is_not_detected(self, date_filter, text):
        # Left for #110, which covers month-and-year dates for full and abbreviated months.
        assert date_filter.detect(text) == []

    def test_spelled_out_months_still_detected(self, date_filter):
        for date in ("September 10, 1950", "10 September 1950", "May 5, 2020", "June 1 1999", "July 4, 1976"):
            assert _texts(date_filter.detect(f"It was on {date}.")) == [date]


class TestRegexDoesNotValidateCalendar:
    """The patterns are regex-only; they do not validate day-in-month.

    These are characterization facts of the current implementation, not an
    endorsement of the dates as calendar-valid.
    """

    @pytest.mark.parametrize(
        "text",
        [
            "1990-02-30",
            "February 30, 1990",
        ],
    )
    def test_impossible_day_still_matched(self, date_filter, text):
        assert text in _texts(date_filter.detect(text))


class TestMultipleMatches:
    def test_two_slash_dates(self, date_filter):
        spans = date_filter.detect("01/15/1990 and 02/20/1991")
        assert _texts(spans) == ["01/15/1990", "02/20/1991"]

    def test_mixed_formats(self, date_filter):
        spans = date_filter.detect("From 1990-01-15 to January 15, 1990")
        texts = _texts(spans)
        assert "1990-01-15" in texts
        assert "January 15, 1990" in texts


class TestReturnShape:
    def test_returns_list(self, date_filter):
        assert isinstance(date_filter.detect("01/15/1990"), list)

    def test_empty_input_returns_empty_list(self, date_filter):
        assert date_filter.detect("") == []
