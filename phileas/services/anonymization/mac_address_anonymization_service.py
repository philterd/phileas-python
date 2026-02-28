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


class MACAddressAnonymizationService(AbstractAnonymizationService):
    """Anonymization service for MAC address values."""

    def anonymize(self, token: str) -> str:
        octets = [random.randint(0, 255) for _ in range(6)]
        return ":".join(f"{o:02X}" for o in octets)
