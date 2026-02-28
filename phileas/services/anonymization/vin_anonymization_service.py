from __future__ import annotations

import random

from .base import AbstractAnonymizationService

# VIN characters exclude I, O, and Q
_VIN_CHARS = "ABCDEFGHJKLMNPRSTUVWXYZ0123456789"


class VINAnonymizationService(AbstractAnonymizationService):
    """Anonymization service for Vehicle Identification Number (VIN) values."""

    def anonymize(self, token: str) -> str:
        return "".join(random.choices(_VIN_CHARS, k=17))
