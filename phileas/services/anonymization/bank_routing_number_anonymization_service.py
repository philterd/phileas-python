from __future__ import annotations

import random

from .base import AbstractAnonymizationService


class BankRoutingNumberAnonymizationService(AbstractAnonymizationService):
    """Anonymization service for bank routing number values."""

    def anonymize(self, token: str) -> str:
        # ABA routing numbers: first two digits are 01-12 or 21-32
        prefixes = list(range(1, 13)) + list(range(21, 33))
        prefix = random.choice(prefixes)
        suffix = random.randint(0, 9999999)
        return f"{prefix:02d}{suffix:07d}"
