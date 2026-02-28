from __future__ import annotations

import random

from .base import AbstractAnonymizationService


class CurrencyAnonymizationService(AbstractAnonymizationService):
    """Anonymization service for currency values."""

    def anonymize(self, token: str) -> str:
        dollars = random.randint(1, 9999)
        cents = random.randint(0, 99)
        return f"${dollars}.{cents:02d}"
