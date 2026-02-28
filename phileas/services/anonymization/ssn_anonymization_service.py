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

from .base import AbstractAnonymizationService


class SSNAnonymizationService(AbstractAnonymizationService):
    """Anonymization service for Social Security Number values."""

    def anonymize(self, token: str) -> str:
        # Generate a random SSN avoiding invalid prefixes (000, 666, 900-999)
        while True:
            area = random.randint(1, 899)
            if area == 666:
                continue
            break
        group = random.randint(1, 99)
        serial = random.randint(1, 9999)
        return f"{area:03d}-{group:02d}-{serial:04d}"
