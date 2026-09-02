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

from phileas.filters.ein_filter import VALID_PREFIXES
from .base import AbstractAnonymizationService

# Sorted: a set's iteration order is not stable.
_PREFIXES = sorted(VALID_PREFIXES)


class EINAnonymizationService(AbstractAnonymizationService):
    """Anonymization service for Employer Identification Number values."""

    def anonymize(self, token: str) -> str:
        # An issued prefix, so the result survives ``onlyValidPrefixes``.
        return f"{random.choice(_PREFIXES)}-{random.randint(0, 9999999):07d}"
