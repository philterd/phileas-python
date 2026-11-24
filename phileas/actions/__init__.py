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
Policy actions — the behavior behind each redaction strategy.

The *vocabulary* of strategies (which exist, the ``phileas_enum`` value used in
policy JSON, and the JSON field each argument maps to) is owned by the PhiSQL
catalog and reached through :mod:`phileas.catalog`. This module owns the
*behavior*: one handler per strategy, keyed by the catalog's ``phileas_enum``.

A handler has the signature
``(strategy, config, filter_type, token, classification) -> str`` where
``strategy`` is the catalog :class:`phisql.catalog.Strategy` (used to resolve
argument field names), ``config`` is the strategy object from the policy JSON,
and ``classification`` is the span's label (``%l`` in a redaction format).
The ``SHIFT`` handler also takes the filter context and the context service, where
it keeps a context's random date shift.

Strategies that require externally-configured key material — ``ENCRYPT``
(CRYPTO_REPLACE), ``FPE_ENCRYPT`` (FPE_ENCRYPT_REPLACE) — are not executed by
this reference engine; they emit a stable marker.

A handler never returns the original token: when a strategy cannot be applied
to a value (an unparseable date, a value too short to reduce, a filter type
with no anonymization service) the value is redacted instead.
"""

from __future__ import annotations

import hashlib
from datetime import date
from typing import Callable, Dict, Optional, Tuple

from phisql.catalog import Strategy

from phileas.catalog import get_catalog
from .date_ops import parse_date, random_shift_days, relative_date, shift_date, truncate_to_year

DEFAULT_REDACTION_FORMAT = "{{{REDACTED-%t}}}"

Action = Callable[[Optional[Strategy], dict, str, str, str], str]


def _field(strategy: Optional[Strategy], arg_name: str, default: str) -> str:
    """Resolves the policy-JSON field name for *arg_name* from the catalog."""
    if strategy is not None:
        arg = strategy.find_arg(arg_name)
        if arg is not None and arg.phileas_field:
            return arg.phileas_field
    return default


def _to_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_bool(value) -> bool:
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return bool(value)


def _mask_length(value, default: int) -> int:
    """Resolves the mask length, returning *default* for the full token length.

    The catalog types ``mask_length`` as a string, so the policy value may be an
    int, a numeric string (e.g. ``"4"``), or ``"SAME"``/``None`` meaning "mask
    the whole value".
    """
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value if value > 0 else default
    if isinstance(value, str) and value.strip().isdigit():
        n = int(value.strip())
        return n if n > 0 else default
    return default


# --- Action handlers (keyed below by PhiSQL keyword) -------------------------


def _redact(strategy, config, filter_type, token, classification=""):
    # Literal substitutions, in the same order as Phileas (Java): %t is the filter
    # type, %l the classification (empty when there is none), and %v the value.
    fmt = config.get(_field(strategy, "format", "redactionFormat")) or DEFAULT_REDACTION_FORMAT
    return fmt.replace("%t", filter_type).replace("%l", classification or "").replace("%v", token)


def _mask(strategy, config, filter_type, token, classification=""):
    mask_char = config.get(_field(strategy, "mask_char", "maskCharacter")) or "*"
    length = _mask_length(config.get(_field(strategy, "mask_length", "maskLength")), len(token))
    return mask_char * length


def _random_replace(strategy, config, filter_type, token, classification=""):
    from phileas.services.anonymization import get_anonymization_service

    service = get_anonymization_service(filter_type)
    if service is None:
        return _redact(strategy, config, filter_type, token, classification)
    return service.anonymize(token)


def _static_replace(strategy, config, filter_type, token, classification=""):
    return config.get(_field(strategy, "value", "staticReplacement"), "")


def _encrypt(strategy, config, filter_type, token, classification=""):
    # CRYPTO_REPLACE needs a key configured via PhiSQL "CONFIGURE CRYPTO"; this
    # reference engine does not perform encryption and emits a stable marker.
    return "{{{ENCRYPTED-%t}}}".replace("%t", filter_type)


def _fpe_encrypt(strategy, config, filter_type, token, classification=""):
    # FPE_ENCRYPT_REPLACE needs a key + tweak configured via "CONFIGURE FPE".
    return "{{{FPE-ENCRYPTED-%t}}}".replace("%t", filter_type)


def _hash_sha256(strategy, config, filter_type, token, classification=""):
    return hashlib.sha256(token.encode()).hexdigest()


def _last_4(strategy, config, filter_type, token, classification=""):
    # Four characters or fewer would be revealed whole.
    if len(token) <= 4:
        return _redact(strategy, config, filter_type, token, classification)
    return "*" * (len(token) - 4) + token[-4:]


def _truncate(strategy, config, filter_type, token, classification=""):
    if len(token) <= 4:
        return _redact(strategy, config, filter_type, token, classification)
    return token[:4]


def _truncate_to_year(strategy, config, filter_type, token, classification=""):
    year = truncate_to_year(token)
    return year if year is not None else _redact(strategy, config, filter_type, token, classification)


# The context value that holds a context's random date shift, in days. A detected
# token cannot contain a NUL character, so the key cannot collide with a token.
CONTEXT_SHIFT_KEY = "\0date-shift"


def _shift(strategy, config, filter_type, token, classification="", context="", context_service=None):
    if _to_bool(config.get(_field(strategy, "random", "shiftRandom"))):
        shifted = _random_shift(strategy, config, token, context, context_service)
    else:
        years = _to_int(config.get(_field(strategy, "years", "shiftYears")))
        months = _to_int(config.get(_field(strategy, "months", "shiftMonths")))
        days = _to_int(config.get(_field(strategy, "days", "shiftDays")))
        shifted = shift_date(token, years, months, days)
    return shifted if shifted is not None else _redact(strategy, config, filter_type, token, classification)


def _random_shift(strategy, config, token, context, context_service) -> Optional[str]:
    """Shifts a date by a random amount; shiftDays, shiftMonths and shiftYears are ignored.

    With the DOCUMENT scope (the default) each date gets its own shift. With the
    CONTEXT scope the shift is drawn for the first date the context sees and kept in
    the context as a number of days, so every date in the context moves by the same
    number of days and keeps its order and the days between it and the others. Days
    rather than months and years: adding a month moves January 30 and January 31
    both to the end of February. Without a context service, each date gets its own
    shift.
    """
    dt = parse_date(token)
    if dt is None:
        return None
    scope = str(config.get(_field(strategy, "scope", "replacementScope")) or "").upper()
    if scope == "CONTEXT" and context_service is not None:
        days = int(context_service.compute_value_if_absent(
            context, CONTEXT_SHIFT_KEY, lambda: str(random_shift_days(dt))
        ))
    else:
        days = random_shift_days(dt)
    return shift_date(token, 0, 0, days)


def _today() -> date:
    return date.today()


def _relative(strategy, config, filter_type, token, classification=""):
    # Future dates are redacted unless futureDates is set, as in the Java engine.
    future_dates = _to_bool(config.get(_field(strategy, "futureDates", "futureDates")))
    relative = relative_date(token, _today(), future_dates)
    return relative if relative is not None else _redact(strategy, config, filter_type, token, classification)


def _abbreviate(strategy, config, filter_type, token, classification=""):
    return "".join(word[0].upper() for word in token.split() if word)


# PhiSQL keyword -> handler. Keys are catalog keywords; the registry below is
# re-keyed by the catalog's phileas_enum so policy JSON (which uses the enum)
# dispatches correctly.
def _map_replace(strategy, config, filter_type, token, classification=""):
    """The inline table, then the fallback.

    Reached by a direct call; FilterService resolves through Strategy, which can
    also reach the policy's generators.
    """
    from phileas.policy.map_replace import MapReplaceResolver

    resolver = MapReplaceResolver(config)
    replacement = resolver.resolve(token, filter_type)
    if replacement is not None:
        return replacement
    return get_replacement(resolver.fallback, config, filter_type, token, classification)


_HANDLERS: Dict[str, Action] = {
    "REDACT": _redact,
    "MASK": _mask,
    "RANDOM_REPLACE": _random_replace,
    "STATIC_REPLACE": _static_replace,
    "ENCRYPT": _encrypt,
    "FPE_ENCRYPT": _fpe_encrypt,
    "HASH_SHA256": _hash_sha256,
    "LAST_4": _last_4,
    "TRUNCATE": _truncate,
    "TRUNCATE_TO_YEAR": _truncate_to_year,
    "SHIFT": _shift,
    "RELATIVE": _relative,
    "ABBREVIATE": _abbreviate,
    "MAP_REPLACE": _map_replace,
}

_registry: Optional[Dict[str, Tuple[Optional[Strategy], Action]]] = None


def _get_registry() -> Dict[str, Tuple[Optional[Strategy], Action]]:
    global _registry
    if _registry is None:
        catalog = get_catalog()
        registry: Dict[str, Tuple[Optional[Strategy], Action]] = {}
        for keyword, handler in _HANDLERS.items():
            strategy = catalog.get_strategy(keyword)
            if strategy is not None:
                registry[strategy.phileas_enum] = (strategy, handler)
        _registry = registry
    return _registry


def is_known(phileas_enum: str) -> bool:
    """Returns True if this engine implements the given strategy enum."""
    return phileas_enum in _get_registry()


def get_replacement(
    phileas_enum: str,
    config: dict,
    filter_type: str,
    token: str,
    classification: str = "",
    context: str = "",
    context_service=None,
) -> str:
    """Computes the replacement for *token* under the strategy *phileas_enum*.

    *classification* is the span's label, used for ``%l`` in a redaction format.
    *context* and *context_service* are passed to the strategies that keep a value
    per context: ``SHIFT`` keeps a context's random date shift there.

    Raises ValueError if the enum is not a catalog strategy this engine
    implements.
    """
    entry = _get_registry().get(phileas_enum)
    if entry is None:
        raise ValueError(f"Unsupported or unknown redaction strategy: {phileas_enum!r}")
    strategy, handler = entry
    if handler is _shift:
        return _shift(strategy, config, filter_type, token, classification, context, context_service)
    return handler(strategy, config, filter_type, token, classification)
