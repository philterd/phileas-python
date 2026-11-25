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
"""The TRUNCATE strategy and its settings, as in Phileas (Java).

Every expected value below is what Phileas (Java) returns for the same strategy JSON and value.
"""

import json

import pytest

from phileas.policy.policy import Policy
from phileas.policy.strategy import Strategy
from phileas.services.filter_service import FilterService


def truncate(strategy_json, filter_type, token):
    return Strategy.from_dict(json.loads(strategy_json)).get_replacement(filter_type, token)


@pytest.mark.parametrize(
    "strategy_json, token, expected",
    [
        # Defaults: keep 4 at the start, replace the rest with *.
        ('{"strategy": "TRUNCATE"}', "abcdefgh", "abcd****"),
        # At most length - 1 characters are kept, so a short value is never returned whole.
        ('{"strategy": "TRUNCATE"}', "abcd", "abc*"),
        ('{"strategy": "TRUNCATE", "truncateDirection": "TRAILING"}', "abcd", "*bcd"),
        ('{"strategy": "TRUNCATE", "truncateLeaveCharacters": 4}', "abcd", "abc*"),
        ('{"strategy": "TRUNCATE", "truncateLeaveCharacters": 5, "truncateDirection": "TRAILING"}', "abc", "*bc"),
        ('{"strategy": "TRUNCATE"}', "a", "*"),
        # A leave count below 1 is treated as 1.
        ('{"strategy": "TRUNCATE", "truncateLeaveCharacters": 0}', "abcdefgh", "a*******"),
        ('{"strategy": "TRUNCATE", "truncateLeaveCharacters": -3}', "abcdefgh", "a*******"),
        ('{"strategy": "TRUNCATE", "truncateLeaveCharacters": 1}', "abcdefgh", "a*******"),
        ('{"strategy": "TRUNCATE", "truncateLeaveCharacters": 5}', "abcdefgh", "abcde***"),
        ('{"strategy": "TRUNCATE", "truncateLeaveCharacters": 10}', "abcdefgh", "abcdefg*"),
        # TRAILING keeps the end, and the direction is case-insensitive.
        ('{"strategy": "TRUNCATE", "truncateDirection": "TRAILING"}', "abcdefgh", "****efgh"),
        ('{"strategy": "TRUNCATE", "truncateDirection": "trailing"}', "abcdefgh", "****efgh"),
        (
            '{"strategy": "TRUNCATE", "truncateCharacter": "#", "truncateDirection": "TRAILING",'
            ' "truncateLeaveCharacters": 2}',
            "abcdefgh",
            "######gh",
        ),
    ],
)
def test_truncate(strategy_json, token, expected):
    assert truncate(strategy_json, "x", token) == expected


@pytest.mark.parametrize(
    "strategy_json, token, expected",
    [
        # A ZIP code is truncated to its five digits, keeping 1 to 4 of them.
        ('{"strategy": "TRUNCATE", "truncateLeaveCharacters": 5}', "90210", "9021*"),
        ('{"strategy": "TRUNCATE", "truncateLeaveCharacters": 6}', "90210", "9021*"),
        ('{"strategy": "TRUNCATE", "truncateLeaveCharacters": 5, "truncateDirection": "TRAILING"}', "90210", "*0210"),
        ('{"strategy": "TRUNCATE", "truncateLeaveCharacters": 0}', "90210", "9****"),
        ('{"strategy": "TRUNCATE"}', "90210-0110", "9021*"),
        ('{"strategy": "TRUNCATE", "truncateLeaveCharacters": 2}', "90210-0110", "90***"),
        ('{"strategy": "TRUNCATE", "truncateLeaveCharacters": 2, "truncateDirection": "TRAILING"}', "90210-0110", "***10"),
        (
            '{"strategy": "TRUNCATE", "truncateCharacter": "#", "truncateLeaveCharacters": 3,'
            ' "truncateDirection": "TRAILING"}',
            "90210-1234",
            "##210",
        ),
    ],
)
def test_truncate_zip_code(strategy_json, token, expected):
    assert truncate(strategy_json, "zip-code", token) == expected


def run(policy_json, text):
    return FilterService().filter(Policy.from_json(policy_json), "ctx", "doc", text).filtered_text


def test_policy_settings_are_applied():
    policy = """
    {
      "name": "truncate",
      "identifiers": {
        "ssn": {
          "ssnFilterStrategies": [
            {"strategy": "TRUNCATE", "truncateLeaveCharacters": 4, "truncateDirection": "TRAILING",
             "truncateCharacter": "X"}
          ]
        }
      }
    }
    """
    assert run(policy, "SSN 123-45-6789 on file.") == "SSN XXXXXXX6789 on file."


def test_policy_defaults():
    policy = '{"name": "truncate", "identifiers": {"ssn": {"ssnFilterStrategies": [{"strategy": "TRUNCATE"}]}}}'
    assert run(policy, "SSN 123-45-6789 on file.") == "SSN 123-******* on file."


@pytest.mark.parametrize(
    "leave, text, expected",
    [
        (5, "Zip 90210 on file.", "Zip 9021* on file."),
        (2, "Zip 90210-0110 on file.", "Zip 90*** on file."),
    ],
)
def test_policy_zip_code(leave, text, expected):
    policy = json.dumps(
        {
            "name": "truncate",
            "identifiers": {
                "zipCode": {"zipCodeFilterStrategy": [{"strategy": "TRUNCATE", "truncateLeaveCharacters": leave}]}
            },
        }
    )
    assert run(policy, text) == expected
