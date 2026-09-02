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
``MAP_REPLACE`` resolution: lookup table, then generator, then fallback.

Anything the table and the generator cannot supply returns None, so the caller
applies ``fallbackStrategy`` and the value is never left in the clear.
"""

from __future__ import annotations

import logging
from typing import Callable, Dict, Optional

from .generators import GeneratorError, build_generator

logger = logging.getLogger(__name__)

DEFAULT_FALLBACK = "REDACT"

# Mapping files are read once per path; a policy is applied to many documents.
_FILE_CACHE: Dict[str, Dict[str, str]] = {}


def load_mapping_file(path: str) -> Dict[str, str]:
    """Read one TSV mapping file: a tab-delimited key and value per row."""
    if path in _FILE_CACHE:
        return _FILE_CACHE[path]

    mappings: Dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.rstrip("\n").rstrip("\r")
                if not line or "\t" not in line:
                    continue
                key, _, value = line.partition("\t")
                mappings[key] = value
    except OSError as error:
        logger.warning("Could not read the mapping file %s: %s", path, error)

    _FILE_CACHE[path] = mappings
    return mappings


class MapReplaceResolver:
    """The lookup table, generator, and validation for one MAP_REPLACE strategy."""

    def __init__(
        self,
        config: dict,
        generators: Optional[dict] = None,
        contains_pii: Optional[Callable[[str], bool]] = None,
    ) -> None:
        self.case_sensitive = bool(config.get("caseSensitive", False))

        # Files in order, then inline over them: inline wins, later file beats earlier.
        table: Dict[str, str] = {}
        for path in config.get("mappingFiles") or []:
            if isinstance(path, str):
                for key, value in load_mapping_file(path).items():
                    table[self._key(key)] = value
        for key, value in (config.get("mappings") or {}).items():
            table[self._key(str(key))] = value
        self.mappings = table

        # The schema's enum excludes MAP_REPLACE, but a hand-written policy could
        # name it and recurse.
        fallback = str(config.get("fallbackStrategy") or DEFAULT_FALLBACK).upper()
        self.fallback = DEFAULT_FALLBACK if fallback == "MAP_REPLACE" else fallback

        name = config.get("generator")
        self.generator = build_generator(name, (generators or {}).get(name)) if name else None
        self._contains_pii = contains_pii
        self._rescanning = False
        self._cache: Dict[tuple, Optional[str]] = {}

    def _key(self, value: str) -> str:
        return value if self.case_sensitive else value.lower()

    def resolve(self, token: str, label: str = "", context: str = "") -> Optional[str]:
        """The mapped or generated replacement, or None to apply the fallback.

        Cached per context, so the generator runs at most once for a value.
        """
        key = (context, token)
        if key not in self._cache:
            self._cache[key] = self._resolve(token, label)
        return self._cache[key]

    def _resolve(self, token: str, label: str) -> Optional[str]:
        mapped = self.mappings.get(self._key(token))
        if mapped is not None:
            return mapped

        # A generated value is re-scanned; invoking a generator there would recurse.
        if self.generator is None or self._rescanning:
            return None

        try:
            generated = self.generator.generate(token, label)
        except GeneratorError as error:
            # The token is not logged.
            logger.warning(
                "Generator '%s' failed; falling back to %s. Reason: %s",
                self.generator.name, self.fallback, error,
            )
            return None

        return generated if self._acceptable(token, generated) else None

    def _acceptable(self, token: str, generated: str) -> bool:
        if not generated or not generated.strip():
            return False

        if generated.strip().lower() == token.strip().lower():
            logger.warning(
                "Generator '%s' returned the original value; falling back to %s.",
                self.generator.name, self.fallback,
            )
            return False

        if self._contains_pii is not None:
            self._rescanning = True
            try:
                if self._contains_pii(generated):
                    logger.warning(
                        "Generator '%s' produced a replacement containing PII; falling back to %s.",
                        self.generator.name, self.fallback,
                    )
                    return False
            finally:
                self._rescanning = False

        return True
