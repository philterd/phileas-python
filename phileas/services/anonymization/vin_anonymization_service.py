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

# VIN characters exclude I, O, and Q
_VIN_CHARS = "ABCDEFGHJKLMNPRSTUVWXYZ0123456789"


class VINAnonymizationService(AbstractAnonymizationService):
    """Anonymization service for Vehicle Identification Number (VIN) values."""

    def anonymize(self, token: str) -> str:
        return "".join(random.choices(_VIN_CHARS, k=17))
