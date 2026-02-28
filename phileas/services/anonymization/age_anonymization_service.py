from __future__ import annotations

import random

from .base import AbstractAnonymizationService


class AgeAnonymizationService(AbstractAnonymizationService):
    """Anonymization service for age values."""

    def anonymize(self, token: str) -> str:
        age = random.randint(1, 99)
        return f"{age} years old"
