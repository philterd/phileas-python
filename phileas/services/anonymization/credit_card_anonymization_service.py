from __future__ import annotations

import random

from .base import AbstractAnonymizationService


class CreditCardAnonymizationService(AbstractAnonymizationService):
    """Anonymization service for credit card number values."""

    def anonymize(self, token: str) -> str:
        # Generate a random Visa-format 16-digit number (starts with 4)
        digits = [4] + [random.randint(0, 9) for _ in range(15)]
        return "".join(str(d) for d in digits)
