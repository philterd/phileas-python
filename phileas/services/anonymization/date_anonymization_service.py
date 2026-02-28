from __future__ import annotations

import random

from .base import AbstractAnonymizationService

_MONTHS = ["January", "February", "March", "April", "May", "June",
           "July", "August", "September", "October", "November", "December"]


class DateAnonymizationService(AbstractAnonymizationService):
    """Anonymization service for date values."""

    def anonymize(self, token: str) -> str:
        month = random.randint(1, 12)
        day = random.randint(1, 28)
        year = random.randint(1950, 2020)
        return f"{month:02d}/{day:02d}/{year}"
