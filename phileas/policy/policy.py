from __future__ import annotations

import json

from .identifiers import Identifiers


class Policy:
    def __init__(self, name: str = "default"):
        self.name = name
        self.identifiers = Identifiers()
        self.ignored: list = []
        self.ignored_patterns: list = []

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        policy = cls(name=data.get("name", "default"))
        if "identifiers" in data:
            policy.identifiers = Identifiers.from_dict(data["identifiers"])
        policy.ignored = data.get("ignored", [])
        policy.ignored_patterns = data.get("ignoredPatterns", [])
        return policy

    @classmethod
    def from_json(cls, json_str: str) -> "Policy":
        return cls.from_dict(json.loads(json_str))

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "identifiers": self.identifiers.to_dict(),
            "ignored": self.ignored,
            "ignoredPatterns": self.ignored_patterns,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
