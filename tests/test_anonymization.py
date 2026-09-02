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

"""Tests for anonymization services and the RANDOM_REPLACE action."""

import pytest

from phileas.services.anonymization import get_anonymization_service
from phileas.policy.policy import Policy
from phileas.services.filter_service import FilterService

_FILTER_TYPES = [
    "age", "email-address", "credit-card", "ssn", "ein", "phone-number", "ip-address",
    "url", "zip-code", "vin", "bitcoin-address", "bank-routing-number", "date",
    "mac-address", "currency", "street-address", "tracking-number",
    "drivers-license", "iban-code", "passport-number",
]


class TestAnonymizationServices:
    @pytest.mark.parametrize("filter_type", _FILTER_TYPES)
    def test_registered(self, filter_type):
        service = get_anonymization_service(filter_type)
        assert service is not None
        result = service.anonymize("sample")
        assert isinstance(result, str) and result

    def test_unknown_returns_none(self):
        assert get_anonymization_service("not-a-type") is None


class TestRandomReplaceAction:
    def test_random_replace_email_changes_value(self):
        policy = Policy.from_dict({
            "name": "p",
            "identifiers": {"emailAddress": {"emailAddressFilterStrategies": [{"strategy": "RANDOM_REPLACE"}]}},
        })
        result = FilterService().filter(policy, "ctx", "doc", "Mail john@example.com now.")
        assert "john@example.com" not in result.filtered_text
        # A synthetic email took its place.
        assert "@" in result.filtered_text

    def test_random_replace_unknown_type_passthrough(self):
        # A custom identifier has no anonymization service; RANDOM_REPLACE leaves it.
        policy = Policy.from_dict({
            "name": "p",
            "identifiers": {"identifiers": [{
                "classification": "TICKET", "pattern": r"T-\d+",
                "identifierFilterStrategies": [{"strategy": "RANDOM_REPLACE"}],
            }]},
        })
        result = FilterService().filter(policy, "ctx", "doc", "Ref T-100 here.")
        assert "T-100" in result.filtered_text
