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
"""%t, %l and %v in a redaction format, as in Phileas (Java)."""

import pytest

from phileas import actions
from phileas.policy.policy import Policy
from phileas.services.filter_service import FilterService

FORMAT = "[%t|%l|%v]"


def run(identifiers, text):
    policy = Policy.from_dict({"name": "t", "identifiers": identifiers})
    return FilterService().filter(policy, "ctx", "doc", text).filtered_text


def redact(strategies_field):
    return {strategies_field: [{"strategy": "REDACT", "redactionFormat": FORMAT}]}


@pytest.mark.parametrize(
    "identifiers, text, expected",
    [
        # A filter without a classification has an empty label.
        ({"ssn": redact("ssnFilterStrategies")}, "SSN 123-45-6789 ok", "SSN [ssn||123-45-6789] ok"),
        # The tracking number's carrier is its label.
        (
            {"trackingNumber": redact("trackingNumberFilterStrategies")},
            "Ship 1Z999AA10123456784 now",
            "Ship [tracking-number|ups|1Z999AA10123456784] now",
        ),
        # A custom identifier's classification is its label.
        (
            {
                "identifiers": [
                    {
                        "classification": "mrn",
                        "pattern": r"MRN \d{8}",
                        "identifierFilterStrategies": [{"strategy": "REDACT", "redactionFormat": FORMAT}],
                    }
                ]
            },
            "Record MRN 00482913 ok",
            "Record [mrn|mrn|MRN 00482913] ok",
        ),
        # A custom dictionary's classification is its label.
        (
            {
                "dictionaries": [
                    {
                        "classification": "animal",
                        "terms": ["zebra"],
                        "customFilterStrategies": [{"strategy": "REDACT", "redactionFormat": FORMAT}],
                    }
                ]
            },
            "A zebra x",
            "A [animal|animal|zebra] x",
        ),
    ],
)
def test_placeholders_are_replaced(identifiers, text, expected):
    assert run(identifiers, text) == expected


def test_passport_label_is_the_country():
    filtered = run({"passportNumber": redact("passportNumberFilterStrategies")}, "Passport A12345678 here")
    assert filtered == "Passport [passport-number|US|A12345678] here"


def test_drivers_license_has_no_state_label():
    # States share number formats, so the matched format's state is not used as a label.
    filtered = run(
        {"driversLicense": redact("driversLicenseFilterStrategies")},
        "Driver's license number A1234567 on file",
    )
    assert "%l" not in filtered
    assert "[drivers-license||A1234567]" in filtered


def test_fallback_redaction_gets_the_label():
    # LAST_4 falls back to the redaction format for a value of 4 characters or fewer.
    config = {"strategy": "LAST_4", "redactionFormat": FORMAT}
    assert actions.get_replacement("LAST_4", config, "pattern", "1234", "pin") == "[pattern|pin|1234]"


def test_value_with_regex_replacement_characters_is_inserted_literally():
    config = {"strategy": "REDACT", "redactionFormat": FORMAT}
    assert actions.get_replacement("REDACT", config, "pattern", r"a$1\b", "x") == r"[pattern|x|a$1\b]"


def test_format_without_placeholders_is_unchanged():
    config = {"strategy": "REDACT", "redactionFormat": "{{{REDACTED-%t}}}"}
    assert actions.get_replacement("REDACT", config, "ssn", "123-45-6789") == "{{{REDACTED-ssn}}}"
