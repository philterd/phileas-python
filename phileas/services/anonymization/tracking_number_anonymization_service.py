from __future__ import annotations

import random
import string

from .base import AbstractAnonymizationService


class TrackingNumberAnonymizationService(AbstractAnonymizationService):
    """Anonymization service for tracking number values."""

    def anonymize(self, token: str) -> str:
        # Generate a UPS-style tracking number: 1Z + 16 alphanumeric chars
        chars = string.ascii_uppercase + string.digits
        suffix = "".join(random.choices(chars, k=16))
        return f"1Z{suffix}"
