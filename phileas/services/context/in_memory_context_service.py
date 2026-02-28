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

from __future__ import annotations

from .base import AbstractContextService


class InMemoryContextService(AbstractContextService):
    """In-memory implementation of the context service using a map of maps.

    The structure is: context_name -> {token: replacement}.
    """

    def __init__(self) -> None:
        self._store: dict[str, dict[str, str]] = {}

    def put(self, context: str, token: str, replacement: str) -> None:
        """Store a replacement value for a token under the given context."""
        if context not in self._store:
            self._store[context] = {}
        self._store[context][token] = replacement

    def get(self, context: str, token: str) -> str | None:
        """Return the replacement for a token under the given context, or None if not found."""
        return self._store.get(context, {}).get(token)

    def contains(self, context: str, token: str) -> bool:
        """Return True if a replacement exists for the token under the given context."""
        return token in self._store.get(context, {})
