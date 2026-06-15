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
Named, post-match validators for the custom ``identifier`` filter.

Redaction policy schema 1.1.0 adds an optional ``validator`` to the identifier
filter: a regex match is kept only if the named validator passes, so a generic
identifier can reject format-valid but checksum-invalid values without embedding
executable code in the policy.

This module is the parity port of the Phileas (Java) ``IdentifierValidators``
dispatch. It provides:

* parsing of the schema's two forms (a bare string ``"luhn"`` or an object
  ``{"name": "luhn", "params": {...}}``),
* a name-to-validator registry, and
* resolution of a policy ``validator`` value to a predicate.

Individual validators (luhn, mod11, and so on) are added by their own issues and
registered with :func:`register_validator`. An unknown or not-yet-implemented
name is a loud error, never silently ignored.
"""

from __future__ import annotations

from typing import Callable, Dict, Optional, Tuple

# A validator factory takes the optional ``params`` dict and returns a predicate
# that returns True when the matched text passes.
ValidatorFactory = Callable[[Optional[dict]], Callable[[str], bool]]

# Registry of built-in identifier validators by name. Empty until a validator
# issue registers an implementation.
_VALIDATORS: Dict[str, ValidatorFactory] = {}


def register_validator(name: str, factory: ValidatorFactory) -> None:
    """Register a named validator factory.

    Intended for the per-validator modules (and tests). ``factory`` receives the
    optional params dict and returns a ``(text: str) -> bool`` predicate.
    """
    _VALIDATORS[name] = factory


def _parse(spec) -> Tuple[Optional[str], Optional[dict]]:
    """Normalize the policy ``validator`` value to ``(name, params)``.

    Accepts the schema's string form (``"luhn"``) and object form
    (``{"name": "luhn", "params": {...}}``).
    """
    if isinstance(spec, str):
        return spec, None
    if isinstance(spec, dict):
        return spec.get("name"), spec.get("params")
    raise ValueError(
        "An identifier validator must be a string or an object with a 'name'."
    )


def resolve_validator(spec) -> Optional[Callable[[str], bool]]:
    """Resolve the policy ``validator`` field to a predicate, or ``None``.

    Returns ``None`` when no validator is declared (meaning: keep every match).
    Raises ``ValueError`` when the name is empty, unknown, or not implemented in
    this build, so a policy can never silently skip the check it asked for.
    """
    if spec is None:
        return None

    name, params = _parse(spec)

    if not name:
        raise ValueError("An identifier validator must have a non-empty name.")

    factory = _VALIDATORS.get(name)
    if factory is None:
        implemented = ", ".join(sorted(_VALIDATORS)) or "(none)"
        raise ValueError(
            f"Unsupported identifier validator '{name}'. "
            f"This build implements: {implemented}."
        )

    return factory(params)


# Register the built-in validators. Imported at the end so that the validator
# modules (which import ``register_validator`` from this module) see it already
# defined, avoiding a circular import.
from . import identifier_validators as _identifier_validators  # noqa: E402,F401
