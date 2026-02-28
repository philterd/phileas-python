from __future__ import annotations

import random

from .base import AbstractAnonymizationService


class PhoneNumberAnonymizationService(AbstractAnonymizationService):
    """Anonymization service for phone number values."""

    def anonymize(self, token: str) -> str:
        # Generate a random NANP-format phone number (NXX-NXX-XXXX)
        area = random.randint(200, 999)
        exchange = random.randint(200, 999)
        subscriber = random.randint(0, 9999)
        return f"{area}-{exchange}-{subscriber:04d}"
