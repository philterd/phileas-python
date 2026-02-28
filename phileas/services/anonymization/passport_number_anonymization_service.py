from __future__ import annotations

import random
import string

from .base import AbstractAnonymizationService


class PassportNumberAnonymizationService(AbstractAnonymizationService):
    """Anonymization service for passport number values."""

    def anonymize(self, token: str) -> str:
        # Generate a random US-format passport: one letter followed by 8 digits
        letter = random.choice(string.ascii_uppercase)
        digits = "".join(str(random.randint(0, 9)) for _ in range(8))
        return f"{letter}{digits}"
