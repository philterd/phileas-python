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
