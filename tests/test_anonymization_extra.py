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

"""Characterization tests for phileas.services.anonymization registry and outputs."""

import re

import pytest

from phileas.services.anonymization import get_anonymization_service

# All 19 registered filter types.
_FILTER_TYPES = [
    "age", "email-address", "credit-card", "ssn", "ein", "phone-number", "ip-address",
    "url", "zip-code", "vin", "bitcoin-address", "bank-routing-number", "date",
    "mac-address", "currency", "street-address", "tracking-number",
    "drivers-license", "iban-code", "passport-number",
]

# Number of repetitions used to exercise the randomness without throwing.
_REPS = 25


class TestRegistry:
    def test_all_20_types_registered(self):
        assert len(_FILTER_TYPES) == 20
        for filter_type in _FILTER_TYPES:
            assert get_anonymization_service(filter_type) is not None

    @pytest.mark.parametrize("filter_type", _FILTER_TYPES)
    def test_service_returns_nonempty_str(self, filter_type):
        service = get_anonymization_service(filter_type)
        assert service is not None
        result = service.anonymize("sample")
        assert isinstance(result, str)
        assert result != ""

    @pytest.mark.parametrize("filter_type", _FILTER_TYPES)
    def test_repeated_calls_never_throw(self, filter_type):
        service = get_anonymization_service(filter_type)
        for _ in range(_REPS):
            result = service.anonymize("sample")
            assert isinstance(result, str) and result

    @pytest.mark.parametrize("bad", ["not-a-type", "", "AGE", "email", "person"])
    def test_unknown_type_returns_none(self, bad):
        assert get_anonymization_service(bad) is None


def _all(filter_type):
    """Run the anonymizer many times and return every output."""
    service = get_anonymization_service(filter_type)
    return [service.anonymize("sample") for _ in range(_REPS)]


class TestTypePlausibleStructure:
    def test_age_has_digits_and_years(self):
        for out in _all("age"):
            assert any(c.isdigit() for c in out)
            assert "years old" in out

    def test_email_contains_at_and_dot(self):
        for out in _all("email-address"):
            assert "@" in out
            local, _, domain = out.partition("@")
            assert local
            assert "." in domain

    def test_credit_card_16_digits(self):
        for out in _all("credit-card"):
            assert out.isdigit()
            assert len(out) == 16

    def test_ssn_format(self):
        pattern = re.compile(r"^\d{3}-\d{2}-\d{4}$")
        for out in _all("ssn"):
            assert pattern.match(out)

    def test_phone_number_has_digits(self):
        pattern = re.compile(r"^\d{3}-\d{3}-\d{4}$")
        for out in _all("phone-number"):
            assert pattern.match(out)
            assert sum(c.isdigit() for c in out) == 10

    def test_ip_address_has_dots_or_colons(self):
        for out in _all("ip-address"):
            assert ("." in out) or (":" in out)
            assert any(c.isdigit() for c in out)

    def test_ipv4_four_octets(self):
        for out in _all("ip-address"):
            if "." in out and ":" not in out:
                octets = out.split(".")
                assert len(octets) == 4
                for o in octets:
                    assert o.isdigit()
                    assert 0 <= int(o) <= 255

    def test_url_starts_with_http(self):
        for out in _all("url"):
            assert out.startswith("http")
            assert "://" in out

    def test_zip_code_five_digits(self):
        for out in _all("zip-code"):
            assert out.isdigit()
            assert len(out) == 5

    def test_vin_alnum_len_17(self):
        for out in _all("vin"):
            assert out.isalnum()
            assert len(out) == 17

    def test_bitcoin_address_starts_with_1(self):
        for out in _all("bitcoin-address"):
            assert out.startswith("1")
            assert out.isalnum()
            assert len(out) > 20

    def test_bank_routing_number_nine_digits(self):
        for out in _all("bank-routing-number"):
            assert out.isdigit()
            assert len(out) == 9

    def test_date_has_digits_and_slashes(self):
        pattern = re.compile(r"^\d{2}/\d{2}/\d{4}$")
        for out in _all("date"):
            assert pattern.match(out)

    def test_mac_address_has_separators(self):
        pattern = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
        for out in _all("mac-address"):
            assert ":" in out
            assert pattern.match(out)

    def test_currency_has_dollar_and_digits(self):
        for out in _all("currency"):
            assert out.startswith("$")
            assert any(c.isdigit() for c in out)
            assert "." in out

    def test_street_address_has_digits_and_space(self):
        for out in _all("street-address"):
            assert any(c.isdigit() for c in out)
            assert " " in out

    def test_tracking_number_starts_with_1z(self):
        for out in _all("tracking-number"):
            assert out.upper().startswith("1Z")
            assert out.isalnum()

    def test_drivers_license_nonempty_alnum(self):
        for out in _all("drivers-license"):
            assert out.isalnum()
            assert any(c.isdigit() for c in out)

    def test_iban_code_starts_with_gb(self):
        for out in _all("iban-code"):
            assert out.upper().startswith("GB")
            assert out.isalnum()
            assert any(c.isdigit() for c in out)

    def test_passport_number_nonempty(self):
        for out in _all("passport-number"):
            assert isinstance(out, str) and out
            assert out.isalnum()


class TestRandomness:
    @pytest.mark.parametrize(
        "filter_type",
        ["email-address", "credit-card", "ssn", "ip-address", "url"],
    )
    def test_outputs_vary_across_calls(self, filter_type):
        # These generators are random; over many reps we expect more than one value.
        outs = _all(filter_type)
        assert len(set(outs)) > 1

    @pytest.mark.parametrize("filter_type", _FILTER_TYPES)
    def test_input_value_not_echoed(self, filter_type):
        service = get_anonymization_service(filter_type)
        for _ in range(5):
            assert service.anonymize("UNIQUE_INPUT_TOKEN") != "UNIQUE_INPUT_TOKEN"
