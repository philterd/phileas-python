from __future__ import annotations

from abc import ABC, abstractmethod


class AbstractAnonymizationService(ABC):
    """Base class for all PII anonymization services."""

    @abstractmethod
    def anonymize(self, token: str) -> str:
        """Return a random replacement value for the given token."""
        ...
