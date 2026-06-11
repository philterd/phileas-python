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
``{"strategy": "MASK", "maskCharacter": "X", "conditions": "confidence > 0.9"}``.
This wrapper exposes its ``strategy`` enum and ``conditions``, evaluates the
condition, and computes a replacement by dispatching to :mod:`phileas.actions`
(keyed by the catalog's ``phileas_enum``). It deliberately holds no per-strategy
field knowledge of its own — the catalog owns that.
"""

from __future__ import annotations

from typing import Optional

from phileas.actions import DEFAULT_REDACTION_FORMAT, get_replacement
from .conditions import evaluate


class Strategy:
    """Wraps one strategy object from a policy's filter-strategies array."""

    def __init__(self, config: Optional[dict] = None) -> None:
        self.config = dict(config) if config else {"strategy": "REDACT"}
        self.strategy = self.config.get("strategy", "REDACT")
        self.conditions = self.config.get("conditions", "") or ""

    @classmethod
    def from_dict(cls, data: dict) -> "Strategy":
        return cls(data)

    @classmethod
    def default(cls) -> "Strategy":
        """Returns a default REDACT strategy (used when a filter declares none)."""
        return cls({"strategy": "REDACT", "redactionFormat": DEFAULT_REDACTION_FORMAT})

    def evaluate_condition(self, token: str, context: str, confidence: float) -> bool:
        """Returns True if this strategy's condition is satisfied."""
        return evaluate(self.conditions, token, context, confidence)

    def get_replacement(self, filter_type: str, token: str) -> str:
        """Returns the replacement value for *token* under this strategy."""
        return get_replacement(self.strategy, self.config, filter_type, token)

    def to_dict(self) -> dict:
        return dict(self.config)
