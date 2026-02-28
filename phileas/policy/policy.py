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

import json

import yaml

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

    @classmethod
    def from_yaml(cls, yaml_str: str) -> "Policy":
        return cls.from_dict(yaml.safe_load(yaml_str))

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "identifiers": self.identifiers.to_dict(),
            "ignored": self.ignored,
            "ignoredPatterns": self.ignored_patterns,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def to_yaml(self) -> str:
        return yaml.dump(self.to_dict(), default_flow_style=False, allow_unicode=True)
