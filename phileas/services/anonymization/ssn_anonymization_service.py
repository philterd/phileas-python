from __future__ import annotations

import random

from .base import AbstractAnonymizationService


class SSNAnonymizationService(AbstractAnonymizationService):
    """Anonymization service for Social Security Number values."""

    def anonymize(self, token: str) -> str:
        # Generate a random SSN avoiding invalid prefixes (000, 666, 900-999)
        while True:
            area = random.randint(1, 899)
            if area == 666:
                continue
            break
        group = random.randint(1, 99)
        serial = random.randint(1, 9999)
        return f"{area:03d}-{group:02d}-{serial:04d}"
