"""Tests for policy serialization and deserialization."""

import json
import yaml
import pytest

from phileas.policy.filter_strategy import FilterStrategy
from phileas.policy.identifiers import Identifiers, EmailAddressFilterConfig, AgeFilterConfig
from phileas.policy.policy import Policy


class TestFilterStrategy:
    def test_defaults(self):
        s = FilterStrategy()
        assert s.strategy == "REDACT"
        assert s.redaction_format == "{{{REDACTED-%t}}}"

    def test_from_dict(self):
        d = {"strategy": "MASK", "maskCharacter": "#", "maskLength": "SAME"}
        s = FilterStrategy.from_dict(d)
        assert s.strategy == "MASK"
        assert s.mask_character == "#"

    def test_to_dict(self):
        s = FilterStrategy(strategy="STATIC_REPLACE", static_replacement="REMOVED")
        d = s.to_dict()
        assert d["strategy"] == "STATIC_REPLACE"
        assert d["staticReplacement"] == "REMOVED"

    def test_round_trip(self):
        s = FilterStrategy(strategy="HASH_SHA256_REPLACE")
        assert FilterStrategy.from_dict(s.to_dict()).strategy == "HASH_SHA256_REPLACE"


class TestIdentifiers:
    def test_empty(self):
        ids = Identifiers()
        assert ids.email_address is None
        assert ids.ssn is None

    def test_from_dict_email(self):
        d = {
            "emailAddress": {
                "enabled": True,
                "emailAddressFilterStrategies": [{"strategy": "REDACT"}],
            }
        }
        ids = Identifiers.from_dict(d)
        assert ids.email_address is not None
        assert ids.email_address.enabled is True
        assert ids.email_address.email_address_filter_strategies[0].strategy == "REDACT"

    def test_from_dict_multiple(self):
        d = {
            "emailAddress": {"enabled": True},
            "ssn": {"enabled": False},
            "age": {"enabled": True},
        }
        ids = Identifiers.from_dict(d)
        assert ids.email_address is not None
        assert ids.ssn is not None
        assert ids.ssn.enabled is False
        assert ids.age is not None

    def test_to_dict_round_trip(self):
        ids = Identifiers()
        ids.email_address = EmailAddressFilterConfig()
        ids.age = AgeFilterConfig()
        d = ids.to_dict()
        ids2 = Identifiers.from_dict(d)
        assert ids2.email_address is not None
        assert ids2.age is not None


class TestPolicy:
    def test_default_policy(self):
        p = Policy()
        assert p.name == "default"
        assert p.ignored == []

    def test_from_dict(self):
        d = {
            "name": "test-policy",
            "identifiers": {
                "emailAddress": {
                    "emailAddressFilterStrategies": [{"strategy": "REDACT"}]
                }
            },
            "ignored": ["noreply@example.com"],
        }
        p = Policy.from_dict(d)
        assert p.name == "test-policy"
        assert p.identifiers.email_address is not None
        assert p.ignored == ["noreply@example.com"]

    def test_from_json(self):
        json_str = json.dumps({
            "name": "json-policy",
            "identifiers": {
                "age": {"ageFilterStrategies": [{"strategy": "MASK"}]}
            },
        })
        p = Policy.from_json(json_str)
        assert p.name == "json-policy"
        assert p.identifiers.age is not None
        assert p.identifiers.age.age_filter_strategies[0].strategy == "MASK"

    def test_to_json(self):
        p = Policy(name="my-policy")
        p.identifiers.ssn = __import__(
            "phileas.policy.identifiers", fromlist=["SSNFilterConfig"]
        ).SSNFilterConfig()
        j = p.to_json()
        data = json.loads(j)
        assert data["name"] == "my-policy"
        assert "ssn" in data["identifiers"]

    def test_round_trip_json(self):
        p = Policy(name="round-trip")
        p.identifiers.email_address = EmailAddressFilterConfig(
            email_address_filter_strategies=[
                FilterStrategy(strategy="STATIC_REPLACE", static_replacement="[EMAIL]")
            ]
        )
        j = p.to_json()
        p2 = Policy.from_json(j)
        assert p2.name == "round-trip"
        strat = p2.identifiers.email_address.email_address_filter_strategies[0]
        assert strat.strategy == "STATIC_REPLACE"
        assert strat.static_replacement == "[EMAIL]"

    def test_ignored_patterns_round_trip(self):
        d = {"name": "p", "identifiers": {}, "ignoredPatterns": [r"\d{3}-test"]}
        p = Policy.from_dict(d)
        assert p.ignored_patterns == [r"\d{3}-test"]
        assert Policy.from_json(p.to_json()).ignored_patterns == [r"\d{3}-test"]

    def test_from_yaml(self):
        yaml_str = (
            "name: yaml-policy\n"
            "identifiers:\n"
            "  age:\n"
            "    ageFilterStrategies:\n"
            "    - strategy: MASK\n"
        )
        p = Policy.from_yaml(yaml_str)
        assert p.name == "yaml-policy"
        assert p.identifiers.age is not None
        assert p.identifiers.age.age_filter_strategies[0].strategy == "MASK"

    def test_to_yaml(self):
        p = Policy(name="my-yaml-policy")
        p.identifiers.ssn = __import__(
            "phileas.policy.identifiers", fromlist=["SSNFilterConfig"]
        ).SSNFilterConfig()
        y = p.to_yaml()
        data = yaml.safe_load(y)
        assert data["name"] == "my-yaml-policy"
        assert "ssn" in data["identifiers"]

    def test_round_trip_yaml(self):
        p = Policy(name="round-trip-yaml")
        p.identifiers.email_address = EmailAddressFilterConfig(
            email_address_filter_strategies=[
                FilterStrategy(strategy="STATIC_REPLACE", static_replacement="[EMAIL]")
            ]
        )
        y = p.to_yaml()
        p2 = Policy.from_yaml(y)
        assert p2.name == "round-trip-yaml"
        strat = p2.identifiers.email_address.email_address_filter_strategies[0]
        assert strat.strategy == "STATIC_REPLACE"
        assert strat.static_replacement == "[EMAIL]"

    def test_yaml_ignored_patterns_round_trip(self):
        d = {"name": "p", "identifiers": {}, "ignoredPatterns": [r"\d{3}-test"]}
        p = Policy.from_dict(d)
        assert Policy.from_yaml(p.to_yaml()).ignored_patterns == [r"\d{3}-test"]

    def test_all_identifier_types_from_dict(self):
        d = {
            "name": "all",
            "identifiers": {
                "age": {},
                "emailAddress": {},
                "creditCard": {},
                "ssn": {},
                "phoneNumber": {},
                "ipAddress": {},
                "url": {},
                "zipCode": {},
                "vin": {},
                "bitcoinAddress": {},
                "bankRoutingNumber": {},
                "date": {},
                "macAddress": {},
                "currency": {},
                "streetAddress": {},
                "trackingNumber": {},
                "driversLicense": {},
                "ibanCode": {},
                "passportNumber": {},
                "phEye": [{"endpoint": "http://pheye:8080"}],
                "custom": [{"enabled": True}],
            },
        }
        p = Policy.from_dict(d)
        ids = p.identifiers
        assert ids.age is not None
        assert ids.email_address is not None
        assert ids.credit_card is not None
        assert ids.ssn is not None
        assert ids.phone_number is not None
        assert ids.ip_address is not None
        assert ids.url is not None
        assert ids.zip_code is not None
        assert ids.vin is not None
        assert ids.bitcoin_address is not None
        assert ids.bank_routing_number is not None
        assert ids.date is not None
        assert ids.mac_address is not None
        assert ids.currency is not None
        assert ids.street_address is not None
        assert ids.tracking_number is not None
        assert ids.drivers_license is not None
        assert ids.iban_code is not None
        assert ids.passport_number is not None
        assert len(ids.ph_eye) == 1
        assert ids.ph_eye[0].endpoint == "http://pheye:8080"
        assert len(ids.custom) == 1
        assert ids.custom[0].enabled is True
