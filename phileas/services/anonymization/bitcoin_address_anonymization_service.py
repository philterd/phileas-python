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

# Base58 alphabet used by Bitcoin addresses (excludes 0, O, I, l)
_BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class BitcoinAddressAnonymizationService(AbstractAnonymizationService):
    """Anonymization service for Bitcoin address values."""

    def anonymize(self, token: str) -> str:
        # Generate a random P2PKH address (starts with 1, 26-34 chars total)
        length = random.randint(25, 33)
        return "1" + "".join(random.choices(_BASE58_CHARS, k=length))
