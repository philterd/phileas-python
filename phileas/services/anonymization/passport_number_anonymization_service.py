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


class PassportNumberAnonymizationService(AbstractAnonymizationService):
    """Anonymization service for passport number values."""

    def anonymize(self, token: str) -> str:
        # Generate a random US-format passport: one letter followed by 8 digits
        letter = random.choice(string.ascii_uppercase)
        digits = "".join(str(random.randint(0, 9)) for _ in range(8))
        return f"{letter}{digits}"
