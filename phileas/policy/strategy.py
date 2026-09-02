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
A single filter strategy from a Phileas policy.

A strategy is just the JSON object emitted by the PhiSQL compiler, e.g.
``{"strategy": "MASK", "maskCharacter": "X", "condition": "confidence > 0.9"}``.
This wrapper exposes its ``strategy`` enum and ``condition``, evaluates the
condition, and computes a replacement by dispatching to :mod:`phileas.actions`
(keyed by the catalog's ``phileas_enum``). It deliberately holds no per-strategy
field knowledge of its own — the catalog owns that.

The condition is read from the ``condition`` key, matching the canonical
redaction policy schema and the Java/.NET Phileas runtimes. The plural
``conditions`` key is accepted as a **deprecated** alias for backward
compatibility and may be removed in a future release.
"""

from __future__ import annotations

from typing import Optional

from phileas.actions import DEFAULT_REDACTION_FORMAT, get_replacement
from .conditions import evaluate


class Strategy:
    """Wraps one strategy object from a policy's filter-strategies array."""

    def __init__(
        self,
        config: Optional[dict] = None,
        generators: Optional[dict] = None,
        contains_pii=None,
    ) -> None:
        self.config = dict(config) if config else {"strategy": "REDACT"}
        self.strategy = self.config.get("strategy", "REDACT")
        # MAP_REPLACE resolves through a lookup table and an optional generator.
        self.map_replace = None
        if str(self.strategy).upper() == "MAP_REPLACE":
            from .map_replace import MapReplaceResolver

            self.map_replace = MapReplaceResolver(self.config, generators, contains_pii)
        # Canonical key is ``condition`` (singular), matching the schema and the
        # Java/.NET runtimes; ``conditions`` is a deprecated alias.
        condition = self.config.get("condition")
        if condition is None:
            condition = self.config.get("conditions")
        self.condition = condition or ""

    @classmethod
    def from_dict(cls, data: dict, generators: Optional[dict] = None, contains_pii=None) -> "Strategy":
        return cls(data, generators, contains_pii)

    @classmethod
    def default(cls) -> "Strategy":
        """Returns a default REDACT strategy (used when a filter declares none)."""
        return cls({"strategy": "REDACT", "redactionFormat": DEFAULT_REDACTION_FORMAT})

    def evaluate_condition(self, token: str, context: str, confidence: float) -> bool:
        """Returns True if this strategy's condition is satisfied."""
        return evaluate(self.condition, token, context, confidence)

    def get_replacement(self, filter_type: str, token: str, context: str = "") -> str:
        """Returns the replacement value for *token* under this strategy."""
        if self.map_replace is not None:
            replacement = self.map_replace.resolve(token, filter_type, context)
            if replacement is not None:
                return replacement
            return get_replacement(
                self.map_replace.fallback, self.config, filter_type, token
            )
        return get_replacement(self.strategy, self.config, filter_type, token)

    def to_dict(self) -> dict:
        return dict(self.config)
