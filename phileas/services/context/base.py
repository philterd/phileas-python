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

from abc import ABC, abstractmethod
from typing import Callable


class AbstractContextService(ABC):
    """Base class for context services that store PII token/replacement pairs."""

    @abstractmethod
    def put(self, context: str, token: str, replacement: str) -> None:
        """Store a replacement value for a token under the given context."""
        ...

    @abstractmethod
    def get(self, context: str, token: str) -> str | None:
        """Return the replacement for a token under the given context, or None if not found."""
        ...

    @abstractmethod
    def contains(self, context: str, token: str) -> bool:
        """Return True if a replacement exists for the token under the given context."""
        ...

    def compute_value_if_absent(self, context: str, key: str, supplier: Callable[[], str]) -> str:
        """Return the context's value for *key*, storing ``supplier()`` first if it has none.

        The date filter keeps a context's random date shift this way. The value is
        stored as a token entry, so use a key no detected token can be, such as one
        containing a NUL character.

        This default calls :meth:`get` and then :meth:`put`, so two calls for the same
        new key at the same time can each store a value. Override it to make the
        check and the store one atomic step.
        """
        value = self.get(context, key)
        if value is None:
            value = supplier()
            self.put(context, key, value)
        return value
