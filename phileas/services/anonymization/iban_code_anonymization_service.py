# Copyright 2026 Philterd, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
