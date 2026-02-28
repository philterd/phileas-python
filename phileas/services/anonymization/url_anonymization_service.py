from __future__ import annotations

import random
import string

from .base import AbstractAnonymizationService


class URLAnonymizationService(AbstractAnonymizationService):
    """Anonymization service for URL values."""

    def anonymize(self, token: str) -> str:
        subdomain = "".join(random.choices(string.ascii_lowercase, k=6))
        return f"https://www.{subdomain}.com"
