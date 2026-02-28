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

_DOMAINS = ["example.com", "sample.org", "test.net", "demo.io"]


class EmailAddressAnonymizationService(AbstractAnonymizationService):
    """Anonymization service for email address values."""

    def anonymize(self, token: str) -> str:
        local = "".join(random.choices(string.ascii_lowercase, k=8))
        domain = random.choice(_DOMAINS)
        return f"{local}@{domain}"
