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
A Phileas redaction policy.

The policy is the JSON document produced by the PhiSQL compiler (or written by
hand against the same schema). Rather than mirror every entity into hand-coded
dataclasses, this class keeps the ``identifiers`` object as raw JSON and lets
:class:`phileas.services.filter_service.FilterService` resolve entity fields and
strategies through the PhiSQL catalog. Top-level allowlists (``ignored`` /
``ignoredPatterns``) are normalized to flat lists for the engine.
"""

from __future__ import annotations

import json
from typing import List

import yaml


def _parse_ignored_terms(raw) -> List[str]:
    """Flattens the policy ``ignored`` value to a list of term strings.

    Accepts the PhiSQL/Phileas shape — a list of ``{"terms": [...]}`` objects —
    as well as a plain list of strings or a single object.
    """
    if isinstance(raw, dict):
        raw = [raw]
    terms: List[str] = []
    for item in raw or []:
        if isinstance(item, str):
            terms.append(item)
        elif isinstance(item, dict):
            terms.extend(item.get("terms", []) or [])
    return terms


def _parse_ignored_patterns(raw) -> List[str]:
    """Flattens ``ignoredPatterns`` to a list of regex strings.

    Accepts the PhiSQL/Phileas shape — a list of ``{"pattern": "..."}`` objects
    — as well as a plain list of strings.
    """
    if isinstance(raw, dict):
        raw = [raw]
    patterns: List[str] = []
    for item in raw or []:
        if isinstance(item, str):
            patterns.append(item)
        elif isinstance(item, dict):
            pattern = item.get("pattern")
            if pattern:
                patterns.append(pattern)
    return patterns


class Policy:
    def __init__(
        self,
        name: str = "default",
        identifiers: dict | None = None,
        ignored: List[str] | None = None,
        ignored_patterns: List[str] | None = None,
        generators: dict | None = None,
    ) -> None:
        self.name = name
        #: Raw Phileas-JSON ``identifiers`` object (entity field -> filter node).
        self.identifiers: dict = identifiers if identifiers is not None else {}
        #: Flat list of policy-level ignored terms.
        self.ignored: List[str] = ignored if ignored is not None else []
        #: Flat list of policy-level ignored regex patterns.
        self.ignored_patterns: List[str] = (
            ignored_patterns if ignored_patterns is not None else []
        )
        #: Named replacement generators, referenced by a MAP_REPLACE strategy.
        self.generators: dict = generators if generators is not None else {}

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        return cls(
            name=data.get("name", "default"),
            identifiers=data.get("identifiers", {}) or {},
            ignored=_parse_ignored_terms(data.get("ignored", [])),
            ignored_patterns=_parse_ignored_patterns(data.get("ignoredPatterns", [])),
            generators=data.get("generators", {}) or {},
        )

    @classmethod
    def from_json(cls, json_str: str) -> "Policy":
        return cls.from_dict(json.loads(json_str))

    @classmethod
    def from_yaml(cls, yaml_str: str) -> "Policy":
        return cls.from_dict(yaml.safe_load(yaml_str))

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "identifiers": self.identifiers,
            "ignored": [{"terms": list(self.ignored)}] if self.ignored else [],
            "ignoredPatterns": [{"pattern": p} for p in self.ignored_patterns],
            **({"generators": self.generators} if self.generators else {}),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def to_yaml(self) -> str:
        return yaml.dump(self.to_dict(), default_flow_style=False, allow_unicode=True)
