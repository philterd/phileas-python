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
"""Selects filter requests for human spot review at the rate a policy's
``config.review.samplingRate`` sets.

Selection is per request and stateless. It has its own random source, so drawing
never changes the values drawn for anonymization or the redacted output.
"""

from __future__ import annotations

import random
from typing import Callable

from phileas.policy.policy import Policy

_RANDOM = random.SystemRandom()


def is_selected(policy: Policy, draw: Callable[[], float] = _RANDOM.random) -> bool:
    """Draw once for a request filtered with *policy*.

    Returns ``True`` if the request is selected for review. Raises ``ValueError``
    if the policy's sampling rate is not from 0.0 to 1.0.
    """
    rate = policy.review_sampling_rate

    # Draws only when the outcome is not already decided. A draw from [0, 1) is always below 1.0.
    if rate == 0.0:
        return False
    if rate == 1.0:
        return True
    return draw() < rate
