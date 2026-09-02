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
"""
Replacement generators, named in a policy's ``generators`` block and invoked by
``MAP_REPLACE``. The endpoint must be local: a detected value is sent to it.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Optional


class GeneratorError(Exception):
    """A generator did not produce a usable value."""


class OllamaGenerator:
    """Calls a local Ollama-compatible ``/api/generate`` endpoint."""

    def __init__(self, name: str, config: dict) -> None:
        self.name = name
        self.endpoint = str(config.get("endpoint") or "").rstrip("/")
        self.model = config.get("model") or ""
        self.prompt = config.get("prompt") or ""
        # Required by the schema, so a generator cannot block the pipeline.
        self.timeout_ms = int(config.get("timeoutMs") or 0)

    @property
    def url(self) -> str:
        return f"{self.endpoint}/api/generate"

    def payload(self, token: str, label: str = "") -> dict:
        prompt = self.prompt.replace("{{token}}", token).replace("{{label}}", label or "")
        # A single complete response rather than a stream of chunks.
        return {"model": self.model, "prompt": prompt, "stream": False}

    def generate(self, token: str, label: str = "") -> str:
        body = json.dumps(self.payload(token, label)).encode("utf-8")
        request = urllib.request.Request(
            self.url,
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_ms / 1000) as response:
                parsed = json.loads(response.read().decode("utf-8"))
        except Exception as error:  # noqa: BLE001 - any failure falls back
            raise GeneratorError(str(error)) from error

        value = parsed.get("response") if isinstance(parsed, dict) else None
        if not isinstance(value, str):
            raise GeneratorError("the endpoint returned no response value")
        # Models often wrap the value in whitespace or newlines.
        return value.strip()


_TYPES = {"ollama": OllamaGenerator}


def build_generator(name: str, config: Optional[dict]):
    """Return the generator named *name*, or None when it is absent or unknown."""
    if not name or not isinstance(config, dict):
        return None
    generator_type = _TYPES.get(str(config.get("type", "")).lower())
    return generator_type(name, config) if generator_type else None
