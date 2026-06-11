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
Evaluator for the ``conditions`` string on a filter strategy.

The PhiSQL compiler emits this string from a ``WHERE`` predicate, e.g.
``"confidence > 0.9"`` or ``"confidence > 0.7 and confidence < 0.95"`` and may
nest with ``or`` and parentheses. Hand-written policies additionally use
``token``/``context`` string tests and ``population`` tests. This module
evaluates the full grammar (``and`` / ``or`` / parentheses) against a concrete
token, context, and confidence.
"""

from __future__ import annotations

import re
from typing import List, Tuple

_WORD_OP = re.compile(r"(and|or)\b", re.IGNORECASE)

_OPS = {
    ">": lambda a, b: a > b,
    "<": lambda a, b: a < b,
    ">=": lambda a, b: a >= b,
    "<=": lambda a, b: a <= b,
    "==": lambda a, b: a == b,
    "=": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
}

Token = Tuple[str, str]


def evaluate(condition: str, token: str, context: str, confidence: float) -> bool:
    """Returns True if *condition* holds (an empty condition always holds)."""
    if not condition or not condition.strip():
        return True
    tokens = _tokenize(condition)
    pos = [0]
    result = _parse_or(tokens, pos, token, context, confidence)
    return result


def _tokenize(s: str) -> List[Token]:
    tokens: List[Token] = []
    buf: List[str] = []
    i = 0
    n = len(s)

    def flush() -> None:
        text = "".join(buf).strip()
        if text:
            tokens.append(("CMP", text))
        buf.clear()

    while i < n:
        c = s[i]
        if c == '"':
            buf.append(c)
            i += 1
            while i < n and s[i] != '"':
                buf.append(s[i])
                i += 1
            if i < n:
                buf.append(s[i])
                i += 1
            continue
        if c == "(":
            flush()
            tokens.append(("LPAREN", "("))
            i += 1
            continue
        if c == ")":
            flush()
            tokens.append(("RPAREN", ")"))
            i += 1
            continue
        at_boundary = i == 0 or s[i - 1].isspace() or s[i - 1] in "()"
        m = _WORD_OP.match(s[i:]) if at_boundary else None
        if m:
            flush()
            op = m.group(1).lower()
            tokens.append(("AND", op) if op == "and" else ("OR", op))
            i += len(m.group(1))
            continue
        buf.append(c)
        i += 1
    flush()
    return tokens


def _parse_or(tokens, pos, token, context, confidence) -> bool:
    value = _parse_and(tokens, pos, token, context, confidence)
    while pos[0] < len(tokens) and tokens[pos[0]][0] == "OR":
        pos[0] += 1
        rhs = _parse_and(tokens, pos, token, context, confidence)
        value = value or rhs
    return value


def _parse_and(tokens, pos, token, context, confidence) -> bool:
    value = _parse_factor(tokens, pos, token, context, confidence)
    while pos[0] < len(tokens) and tokens[pos[0]][0] == "AND":
        pos[0] += 1
        rhs = _parse_factor(tokens, pos, token, context, confidence)
        value = value and rhs
    return value


def _parse_factor(tokens, pos, token, context, confidence) -> bool:
    if pos[0] >= len(tokens):
        return True
    kind, text = tokens[pos[0]]
    if kind == "LPAREN":
        pos[0] += 1
        value = _parse_or(tokens, pos, token, context, confidence)
        if pos[0] < len(tokens) and tokens[pos[0]][0] == "RPAREN":
            pos[0] += 1
        return value
    if kind == "CMP":
        pos[0] += 1
        return _evaluate_leaf(text, token, context, confidence)
    # Stray operator or paren; consume and treat as satisfied.
    pos[0] += 1
    return True


def _evaluate_leaf(condition: str, token: str, context: str, confidence: float) -> bool:
    # token/context == "value"  or  != "value"
    m = re.fullmatch(r'(token|context)\s*(==|!=)\s*"([^"]*)"', condition)
    if m:
        actual = token if m.group(1) == "token" else context
        return (actual == m.group(3)) if m.group(2) == "==" else (actual != m.group(3))

    # token/context startswith|endswith|contains "value"
    m = re.fullmatch(r'(token|context)\s+(startswith|endswith|contains)\s+"([^"]*)"', condition)
    if m:
        actual = token if m.group(1) == "token" else context
        op, needle = m.group(2), m.group(3)
        if op == "startswith":
            return actual.startswith(needle)
        if op == "endswith":
            return actual.endswith(needle)
        return needle in actual

    # confidence <op> number
    m = re.fullmatch(r"confidence\s*(>=|<=|!=|==|=|>|<)\s*([0-9]*\.?[0-9]+)", condition)
    if m:
        return _OPS[m.group(1)](confidence, float(m.group(2)))

    # population <op> number  (zip-code population test)
    m = re.fullmatch(r"population\s*(>=|<=|!=|==|=|>|<)\s*([0-9]+)", condition)
    if m:
        from phileas.policy.zip_code_population import get_population

        population = get_population(token)
        if population is None:
            return False
        return _OPS[m.group(1)](population, int(m.group(2)))

    raise ValueError(f"Unrecognized condition syntax: {condition!r}")
