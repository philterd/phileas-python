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


class BankRoutingNumberAnonymizationService(AbstractAnonymizationService):
    """Anonymization service for bank routing number values."""

    def anonymize(self, token: str) -> str:
        # ABA routing numbers: first two digits are 01-12 or 21-32
        prefixes = list(range(1, 13)) + list(range(21, 33))
        prefix = random.choice(prefixes)
        suffix = random.randint(0, 9999999)
        return f"{prefix:02d}{suffix:07d}"
