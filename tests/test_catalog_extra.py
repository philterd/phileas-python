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

"""Deeper characterization tests for the PhiSQL catalog bridge."""

import pytest

from phileas import actions
from phileas.catalog import PhileasCatalog, get_catalog

# Every built-in entity the engine's detection filters use.
BUILTIN_ENTITIES = (
    "AGE",
    "EMAIL_ADDRESS",
    "CREDIT_CARD",
    "SSN",
    "PHONE_NUMBER",
    "IP_ADDRESS",
    "URL",
    "ZIP_CODE",
    "VIN",
    "BITCOIN_ADDRESS",
    "BANK_ROUTING_NUMBER",
    "DATE",
    "MAC_ADDRESS",
    "CURRENCY",
    "STREET_ADDRESS",
    "TRACKING_NUMBER",
    "DRIVERS_LICENSE",
    "IBAN_CODE",
    "PASSPORT_NUMBER",
)

# Every phileas_enum the action engine implements (policy-JSON strategy values).
ACTION_ENUMS = (
    "REDACT",
    "MASK",
    "RANDOM_REPLACE",
    "STATIC_REPLACE",
    "CRYPTO_REPLACE",
    "FPE_ENCRYPT_REPLACE",
    "HASH_SHA256_REPLACE",
    "LAST_4",
    "TRUNCATE",
    "TRUNCATE_TO_YEAR",
    "SHIFT",
    "RELATIVE",
    "ABBREVIATE",
)


class TestSingletonAndVersion:
    def test_singleton_identity(self):
        assert get_catalog() is get_catalog()

    def test_singleton_type(self):
        assert isinstance(get_catalog(), PhileasCatalog)

    def test_version(self):
        assert get_catalog().version == "v1.0"


class TestEntities:
    @pytest.mark.parametrize("name", BUILTIN_ENTITIES)
    def test_entity_resolves(self, name):
        assert get_catalog().get_entity(name) is not None

    @pytest.mark.parametrize("name", BUILTIN_ENTITIES)
    def test_entity_has_phileas_field(self, name):
        entity = get_catalog().get_entity(name)
        assert entity.phileas_field
        assert isinstance(entity.phileas_field, str)

    @pytest.mark.parametrize("name", BUILTIN_ENTITIES)
    def test_entity_has_strategies_field(self, name):
        entity = get_catalog().get_entity(name)
        assert entity.phileas_strategies_field
        assert isinstance(entity.phileas_strategies_field, str)

    @pytest.mark.parametrize("name", BUILTIN_ENTITIES)
    def test_entity_name_matches_lookup(self, name):
        assert get_catalog().get_entity(name).name == name

    def test_zip_code_singular_strategies_field_is_an_alias(self):
        # ZIP_CODE used a singular strategies field name until schema 1.3.0. The
        # plural is the name to emit; the singular is still read.
        entity = get_catalog().get_entity("ZIP_CODE")
        assert entity.phileas_strategies_field == "zipCodeFilterStrategies"
        assert "zipCodeFilterStrategy" in entity.phileas_strategies_field_aliases

    def test_bitcoin_quirk_abbreviated_strategies_field(self):
        # BITCOIN_ADDRESS uses an abbreviated strategies field name.
        entity = get_catalog().get_entity("BITCOIN_ADDRESS")
        assert entity.phileas_strategies_field == "bitcoinFilterStrategies"

    @pytest.mark.parametrize("name", BUILTIN_ENTITIES)
    def test_case_insensitive_lookup(self, name):
        cat = get_catalog()
        assert cat.get_entity(name.lower()) is cat.get_entity(name)

    @pytest.mark.parametrize("name", BUILTIN_ENTITIES)
    def test_entity_for_field_round_trips(self, name):
        cat = get_catalog()
        entity = cat.get_entity(name)
        round_tripped = cat.entity_for_field(entity.phileas_field)
        assert round_tripped is not None
        assert round_tripped.name == name

    def test_unknown_entity_is_none(self):
        assert get_catalog().get_entity("NOT_A_REAL_ENTITY") is None

    def test_none_entity_is_none(self):
        assert get_catalog().get_entity(None) is None

    def test_entity_for_unknown_field_is_none(self):
        assert get_catalog().entity_for_field("notARealField") is None


class TestStrategies:
    @pytest.mark.parametrize("enum", ACTION_ENUMS)
    def test_strategy_by_enum_resolves(self, enum):
        assert get_catalog().strategy_by_enum(enum) is not None

    @pytest.mark.parametrize("enum", ACTION_ENUMS)
    def test_strategy_enum_round_trips(self, enum):
        strategy = get_catalog().strategy_by_enum(enum)
        assert strategy.phileas_enum == enum

    @pytest.mark.parametrize("enum", ACTION_ENUMS)
    def test_action_is_known(self, enum):
        assert actions.is_known(enum) is True

    def test_strategy_by_enum_none(self):
        assert get_catalog().strategy_by_enum(None) is None

    def test_strategy_by_enum_unknown(self):
        assert get_catalog().strategy_by_enum("NOPE") is None

    def test_crypto_replace_maps_to_encrypt_keyword(self):
        strategy = get_catalog().strategy_by_enum("CRYPTO_REPLACE")
        assert strategy.name == "ENCRYPT"

    def test_hash_enum_maps_to_hash_keyword(self):
        strategy = get_catalog().strategy_by_enum("HASH_SHA256_REPLACE")
        assert strategy.name.upper() == "HASH_SHA256"


class TestFieldForArg:
    @pytest.mark.parametrize(
        "keyword,arg,expected",
        [
            ("MASK", "mask_char", "maskCharacter"),
            ("STATIC_REPLACE", "value", "staticReplacement"),
            ("SHIFT", "days", "shiftDays"),
        ],
    )
    def test_field_for_arg_resolves_known(self, keyword, arg, expected):
        cat = get_catalog()
        strategy = cat.get_strategy(keyword)
        assert cat.field_for_arg(strategy, arg, "fallback") == expected

    def test_field_for_arg_unknown_arg_falls_back(self):
        cat = get_catalog()
        mask = cat.get_strategy("MASK")
        assert cat.field_for_arg(mask, "nonexistent", "fallback") == "fallback"

    def test_field_for_arg_none_strategy_falls_back(self):
        cat = get_catalog()
        assert cat.field_for_arg(None, "mask_char", "fallback") == "fallback"
