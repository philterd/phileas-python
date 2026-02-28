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

_STREET_SUFFIXES = ["Street", "Avenue", "Boulevard", "Road", "Lane", "Drive", "Court", "Place", "Way"]
_STREET_NAMES = ["Main", "Oak", "Maple", "Cedar", "Pine", "Elm", "Washington", "Park", "Lake", "Hill"]


class StreetAddressAnonymizationService(AbstractAnonymizationService):
    """Anonymization service for street address values."""

    def anonymize(self, token: str) -> str:
        number = random.randint(1, 9999)
        name = random.choice(_STREET_NAMES)
        suffix = random.choice(_STREET_SUFFIXES)
        return f"{number} {name} {suffix}"
