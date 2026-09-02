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

"""Tests for the PhiSQL catalog bridge."""

from phileas.catalog import PhileasCatalog, get_catalog


class TestCatalogBridge:
    def test_singleton(self):
        assert get_catalog() is get_catalog()
        assert isinstance(get_catalog(), PhileasCatalog)

    def test_version(self):
        assert get_catalog().version == "v1.0"

    def test_entity_field_mapping(self):
        cat = get_catalog()
        assert cat.get_entity("SSN").phileas_field == "ssn"
        assert cat.get_entity("SSN").phileas_strategies_field == "ssnFilterStrategies"
        assert cat.get_entity("EMAIL_ADDRESS").phileas_field == "emailAddress"

    def test_entity_lookup_case_insensitive(self):
        cat = get_catalog()
        assert cat.get_entity("ssn") is cat.get_entity("SSN")

    def test_quirky_field_names_come_from_catalog(self):
        """The engine must use the catalog's non-obvious field names."""
        cat = get_catalog()
        # zip code was renamed from the singular; the old name stays readable as an alias.
        zip_code = cat.get_entity("ZIP_CODE")
        assert zip_code.phileas_strategies_field == "zipCodeFilterStrategies"
        assert "zipCodeFilterStrategy" in zip_code.phileas_strategies_field_aliases
        # bitcoin uses an abbreviated strategies field name.
        assert cat.get_entity("BITCOIN_ADDRESS").phileas_strategies_field == "bitcoinFilterStrategies"

    def test_entity_for_field(self):
        cat = get_catalog()
        assert cat.entity_for_field("zipCode").name == "ZIP_CODE"

    def test_unknown_entity(self):
        assert get_catalog().get_entity("NOT_A_REAL_ENTITY") is None
        assert get_catalog().get_entity(None) is None

    def test_strategy_by_enum(self):
        cat = get_catalog()
        # PhiSQL keyword HASH_SHA256 -> phileas_enum HASH_SHA256_REPLACE.
        strategy = cat.strategy_by_enum("HASH_SHA256_REPLACE")
        assert strategy is not None
        assert strategy.name.upper() == "HASH_SHA256"

    def test_strategy_by_enum_for_mask(self):
        cat = get_catalog()
        mask = cat.strategy_by_enum("MASK")
        assert mask is not None
        assert mask.find_arg("mask_char").phileas_field == "maskCharacter"

    def test_field_for_arg_uses_catalog(self):
        cat = get_catalog()
        mask = cat.get_strategy("MASK")
        assert cat.field_for_arg(mask, "mask_char", "fallback") == "maskCharacter"
        # Unknown arg falls back to the provided default.
        assert cat.field_for_arg(mask, "nonexistent", "fallback") == "fallback"
        assert cat.field_for_arg(None, "mask_char", "fallback") == "fallback"
