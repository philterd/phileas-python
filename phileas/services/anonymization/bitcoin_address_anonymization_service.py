from __future__ import annotations

import random
import string

from .base import AbstractAnonymizationService

# Base58 alphabet used by Bitcoin addresses (excludes 0, O, I, l)
_BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class BitcoinAddressAnonymizationService(AbstractAnonymizationService):
    """Anonymization service for Bitcoin address values."""

    def anonymize(self, token: str) -> str:
        # Generate a random P2PKH address (starts with 1, 26-34 chars total)
        length = random.randint(25, 33)
        return "1" + "".join(random.choices(_BASE58_CHARS, k=length))
