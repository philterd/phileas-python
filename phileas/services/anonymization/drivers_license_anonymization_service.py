from __future__ import annotations

import random
import string

from .base import AbstractAnonymizationService


class DriversLicenseAnonymizationService(AbstractAnonymizationService):
    """Anonymization service for driver's license number values."""

    def anonymize(self, token: str) -> str:
        # Generate a random driver's license: one letter followed by 8 digits
        letter = random.choice(string.ascii_uppercase)
        digits = "".join(str(random.randint(0, 9)) for _ in range(8))
        return f"{letter}{digits}"
