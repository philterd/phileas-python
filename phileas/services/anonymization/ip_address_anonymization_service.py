from __future__ import annotations

import random

from .base import AbstractAnonymizationService


class IPAddressAnonymizationService(AbstractAnonymizationService):
    """Anonymization service for IP address values."""

    def anonymize(self, token: str) -> str:
        # Generate a random IPv4 address in the 10.x.x.x private range
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
