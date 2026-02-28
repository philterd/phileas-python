from __future__ import annotations

import random

from .base import AbstractAnonymizationService


class MACAddressAnonymizationService(AbstractAnonymizationService):
    """Anonymization service for MAC address values."""

    def anonymize(self, token: str) -> str:
        octets = [random.randint(0, 255) for _ in range(6)]
        return ":".join(f"{o:02X}" for o in octets)
