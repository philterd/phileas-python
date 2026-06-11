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
"""
Bridge to the PhiSQL spec catalog.

phileas-python no longer hand-codes the set of policy actions (redaction
strategies) or the entity-type -> Phileas-JSON field mappings. Both are owned
by the PhiSQL catalog (``spec/v1.0/catalog/*.yaml``) and consumed here through
the ``phisql`` package. The catalog is the single source of truth for:

* which strategies exist, their ``phileas_enum`` (the value of the ``strategy``
  field in policy JSON), and the JSON field name each strategy argument maps to;
* which entity types exist and, for each, the ``identifiers`` field name and the
  filter-strategies array name in policy JSON.

phileas still owns the *behavior* of each action (see :mod:`phileas.actions`),
keyed by the catalog's ``phileas_enum``; the catalog owns the *vocabulary*.

This module relies only on the public ``phisql.Catalog`` lookups
(``get_strategy``/``get_entity``); it discovers the catalog's contents by name
so it can build the reverse ``phileas_enum -> Strategy`` index that policy JSON
requires (policy JSON references strategies by enum, not by PhiSQL keyword).
"""

from __future__ import annotations

from typing import Dict, Optional

from phisql import Catalog as PhisqlCatalog
from phisql.catalog import EntityType, Strategy

# PhiSQL strategy keywords this engine resolves from the catalog. Resolved via
# the public ``Catalog.get_strategy`` so the enum value and argument field names
# come from the catalog, never hard-coded here. A keyword the catalog does not
# know is skipped (keeps phileas forward-compatible with older catalogs).
_STRATEGY_KEYWORDS = (
    "REDACT",
    "MASK",
    "RANDOM_REPLACE",
    "STATIC_REPLACE",
    "ENCRYPT",
    "FPE_ENCRYPT",
    "HASH_SHA256",
    "LAST_4",
    "TRUNCATE",
    "TRUNCATE_TO_YEAR",
    "SHIFT",
    "RELATIVE",
    "ABBREVIATE",
)


def _enumerate_strategy_keywords() -> tuple:
    """Returns every strategy keyword declared in the catalog YAML.

    Falls back to :data:`_STRATEGY_KEYWORDS` if the spec data layout cannot be
    read (e.g. a future ``phisql`` that drops the internal path helper). Either
    way every keyword is resolved through the public catalog API below.
    """
    try:
        import yaml

        from phisql import _paths

        with (_paths.catalog_dir() / "strategies.yaml").open(encoding="utf-8") as fh:
            root = yaml.safe_load(fh)
        names = tuple(item["name"] for item in (root.get("strategies") or []))
        return names or _STRATEGY_KEYWORDS
    except Exception:  # pragma: no cover - defensive fallback
        return _STRATEGY_KEYWORDS


def _enumerate_entity_names() -> Optional[tuple]:
    """Returns every entity-type name declared in the catalog YAML, or None."""
    try:
        import yaml

        from phisql import _paths

        with (_paths.catalog_dir() / "entity-types.yaml").open(encoding="utf-8") as fh:
            root = yaml.safe_load(fh)
        return tuple(item["name"] for item in (root.get("entities") or []))
    except Exception:  # pragma: no cover - defensive fallback
        return None


class PhileasCatalog:
    """Read-only view over the PhiSQL catalog, indexed for engine use."""

    def __init__(self) -> None:
        self._phisql = PhisqlCatalog.load_default()
        self._strategy_by_enum: Dict[str, Strategy] = {}
        self._entity_by_name: Dict[str, EntityType] = {}
        self._entity_by_field: Dict[str, EntityType] = {}

        for keyword in _enumerate_strategy_keywords():
            strategy = self._phisql.get_strategy(keyword)
            if strategy is not None:
                self._strategy_by_enum[strategy.phileas_enum] = strategy

        for name in _enumerate_entity_names() or ():
            entity = self._phisql.get_entity(name)
            if entity is not None:
                self._entity_by_name[entity.name.upper()] = entity
                self._entity_by_field[entity.phileas_field] = entity

    # --- Catalog version -----------------------------------------------------

    @property
    def version(self) -> str:
        """Returns the catalog spec version (e.g. ``"v1.0"``)."""
        return PhisqlCatalog.VERSION

    # --- Entity lookups ------------------------------------------------------

    def get_entity(self, name: Optional[str]) -> Optional[EntityType]:
        """Returns the entity type for a catalog name (case-insensitive)."""
        if name is None:
            return None
        entity = self._phisql.get_entity(name)
        if entity is not None:
            return entity
        return self._entity_by_name.get(name.upper())

    def entity_for_field(self, phileas_field: str) -> Optional[EntityType]:
        """Returns the entity type whose ``identifiers`` field is *phileas_field*."""
        return self._entity_by_field.get(phileas_field)

    # --- Strategy (action) lookups -------------------------------------------

    def get_strategy(self, name: Optional[str]) -> Optional[Strategy]:
        """Returns a strategy by its PhiSQL keyword (case-insensitive)."""
        return self._phisql.get_strategy(name)

    def strategy_by_enum(self, phileas_enum: Optional[str]) -> Optional[Strategy]:
        """Returns the strategy whose ``phileas_enum`` matches the policy JSON value."""
        if phileas_enum is None:
            return None
        return self._strategy_by_enum.get(phileas_enum)

    def field_for_arg(
        self, strategy: Optional[Strategy], arg_name: str, default: str
    ) -> str:
        """Returns the policy-JSON field name for *arg_name* on *strategy*.

        Falls back to *default* when the strategy or argument is unknown, so an
        action can still read a sensibly-named field if the catalog lacks the
        argument (e.g. a hand-written strategy object).
        """
        if strategy is not None:
            arg = strategy.find_arg(arg_name)
            if arg is not None and arg.phileas_field:
                return arg.phileas_field
        return default


_catalog: Optional[PhileasCatalog] = None


def get_catalog() -> PhileasCatalog:
    """Returns the process-wide :class:`PhileasCatalog`, loading it once."""
    global _catalog
    if _catalog is None:
        _catalog = PhileasCatalog()
    return _catalog
