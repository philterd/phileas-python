from __future__ import annotations

from abc import ABC, abstractmethod


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
