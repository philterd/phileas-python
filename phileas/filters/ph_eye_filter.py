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
import urllib.error
import urllib.request
from typing import Any, List

from phileas.models.span import Span
from .base import BaseFilter, FilterType


class PhEyeFilter(BaseFilter):
    """Detects named entities via a ph-eye service or a local GLiNER model.

    Config is a ph-eye node from ``identifiers.pheyes``. Connection settings are
    read from the nested ``phEyeConfiguration`` object (``endpoint``,
    ``labels``); additional options (``bearerToken``, ``timeout``,
    ``thresholds``, ``modelPath``, ``vocabPath``) are read from the node for
    compatibility with hand-written policies.
    """

    def __init__(self, config=None):
        super().__init__(FilterType.PH_EYE, config)
        self._model = None

    def _opt(self, key: str, default: Any) -> Any:
        configuration = self.config.get("phEyeConfiguration") or {}
        if key in configuration:
            return configuration[key]
        return self.config.get(key, default)

    def detect(self, text: str, context: str = "default") -> List[Span]:
        model_path = self._opt("modelPath", "")
        vocab_path = self._opt("vocabPath", "")
        labels = self._opt("labels", ["PERSON"])

        if model_path and vocab_path:
            items = self._predict_local(text, model_path, vocab_path, labels)
        else:
            endpoint = self._opt("endpoint", "")
            if not endpoint:
                return []
            items = self._predict_remote(text, context, endpoint, labels, model_path, vocab_path)

        return self._to_spans(items, context, labels)

    def _predict_remote(self, text, context, endpoint, labels, model_path, vocab_path) -> list:
        bearer_token = self._opt("bearerToken", "")
        timeout = self._opt("timeout", 30) or 30

        payload = json.dumps({
            "text": text,
            "context": context,
            "piece": 0,
            "labels": list(labels),
            "modelPath": model_path,
            "vocabPath": vocab_path,
        }).encode("utf-8")

        req = urllib.request.Request(
            url=endpoint.rstrip("/") + "/find",
            data=payload,
            method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        if bearer_token:
            req.add_header("Authorization", f"Bearer {bearer_token}")

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                response_body = resp.read().decode("utf-8")
        except urllib.error.URLError as exc:
            raise IOError(f"Unable to process document. Request to ph-eye failed: {exc}") from exc

        return json.loads(response_body)

    def _predict_local(self, text, model_path, vocab_path, labels) -> list:
        if not self._model:
            onnx = model_path.endswith(".onnx")
            try:
                from gliner import GLiNER
            except ImportError:
                raise ImportError(
                    "The 'gliner' package is required for local inference. "
                    "Install it with 'pip install gliner'."
                )
            self._model = GLiNER.from_pretrained(model_path, onnx=onnx, vocab_path=vocab_path)
        return self._model.predict_entities(text, labels)

    def _to_spans(self, items: list, context: str, labels) -> List[Span]:
        thresholds = self._opt("thresholds", {}) or {}
        spans: List[Span] = []
        for item in items:
            label = item.get("label", "")
            score = float(item.get("score", 0.0))
            span_text = item.get("text", "")
            start = int(item.get("start", 0))
            end = int(item.get("end", 0))

            if labels and label not in labels:
                continue
            if score < thresholds.get(label.upper(), 0.0):
                continue

            filter_type = "person" if label.upper() == "PERSON" else (label.lower() or FilterType.PH_EYE)
            spans.append(
                Span(
                    character_start=start,
                    character_end=end,
                    filter_type=filter_type,
                    context=context,
                    confidence=score,
                    text=span_text,
                    replacement="",
                    ignored=False,
                )
            )
        return spans
