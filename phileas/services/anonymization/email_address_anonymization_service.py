from __future__ import annotations

import random
import string

from .base import AbstractAnonymizationService

_DOMAINS = ["example.com", "sample.org", "test.net", "demo.io"]


class EmailAddressAnonymizationService(AbstractAnonymizationService):
    """Anonymization service for email address values."""

    def anonymize(self, token: str) -> str:
        local = "".join(random.choices(string.ascii_lowercase, k=8))
        domain = random.choice(_DOMAINS)
        return f"{local}@{domain}"
