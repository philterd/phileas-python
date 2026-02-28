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
