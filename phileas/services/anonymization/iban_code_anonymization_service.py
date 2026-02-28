from __future__ import annotations

import random
import string

from .base import AbstractAnonymizationService


class IBANCodeAnonymizationService(AbstractAnonymizationService):
    """Anonymization service for IBAN code values."""

    def anonymize(self, token: str) -> str:
        # Generate a random GB-format IBAN: GB + 2 check digits + 4 letters + 14 digits
        country = "GB"
        check = f"{random.randint(10, 99)}"
        bank_code = "".join(random.choices(string.ascii_uppercase, k=4))
        account = "".join(str(random.randint(0, 9)) for _ in range(14))
        return f"{country}{check}{bank_code}{account}"
