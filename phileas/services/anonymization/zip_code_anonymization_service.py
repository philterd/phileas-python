from __future__ import annotations

import random

from .base import AbstractAnonymizationService


class ZipCodeAnonymizationService(AbstractAnonymizationService):
    """Anonymization service for ZIP code values."""

    def anonymize(self, token: str) -> str:
        return f"{random.randint(10000, 99999)}"
