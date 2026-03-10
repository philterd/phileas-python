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
from typing import List

from phileas.models.span import Span
from .base import BaseFilter, FilterType


class PhEyeFilter(BaseFilter):
    def __init__(self, filter_config):
        super().__init__(FilterType.PH_EYE, filter_config)
        self._model = None

    def filter(self, text: str, context: str = "default") -> List[Span]:
        model_path = getattr(self.filter_config, "model_path", "")
        vocab_path = getattr(self.filter_config, "vocab_path", "")
        labels = getattr(self.filter_config, "labels", ["PERSON"])

        if model_path and vocab_path:
            return self._local_filter(text, context, model_path, vocab_path, labels)

        endpoint = getattr(self.filter_config, "endpoint", "")
        if not endpoint:
            return []

        thresholds = getattr(self.filter_config, "thresholds", {})
        bearer_token = getattr(self.filter_config, "bearer_token", "")
        timeout = getattr(self.filter_config, "timeout", 30) or 30

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
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        if bearer_token:
            req.add_header("Authorization", f"Bearer {bearer_token}")

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                response_body = resp.read().decode("utf-8")
        except urllib.error.URLError as exc:
            raise IOError(f"Unable to process document. Request to ph-eye failed: {exc}") from exc

        ph_eye_spans = json.loads(response_body)

        strategies = self._get_strategies()
        strategy = strategies[0] if strategies else None
        ignored_terms = set(self._get_ignored())

        spans: List[Span] = []
        for item in ph_eye_spans:
            label = item.get("label", "")
            score = float(item.get("score", 0.0))
            span_text = item.get("text", "")
            start = int(item.get("start", 0))
            end = int(item.get("end", 0))

            if labels and label not in labels:
                continue

            threshold = thresholds.get(label.upper(), 0.0)
            if score < threshold:
                continue

            if span_text in ignored_terms:
                continue

            if label.upper() == "PERSON":
                filter_type = "person"
            else:
                filter_type = label.lower() if label else FilterType.PH_EYE

            replacement = (
                strategy.get_replacement(filter_type, span_text) if strategy else span_text
            )

            spans.append(Span(
                character_start=start,
                character_end=end,
                filter_type=filter_type,
                context=context,
                confidence=score,
                text=span_text,
                replacement=replacement,
                ignored=False,
            ))

        return spans

    def _local_filter(self, text: str, context: str, model_path: str, vocab_path: str, labels: List[str]) -> List[Span]:
        if not self._model:
            onnx = False
            if model_path.endswith(".onnx"):
                onnx = True

            try:
                from gliner import GLiNER
            except ImportError:
                raise ImportError("The 'gliner' package is required for local inference. Install it with 'pip install gliner'.")

            self._model = GLiNER.from_pretrained(model_path, onnx=onnx, vocab_path=vocab_path)

        ph_eye_spans = self._model.predict_entities(text, labels)

        strategies = self._get_strategies()
        strategy = strategies[0] if strategies else None
        ignored_terms = set(self._get_ignored())
        thresholds = getattr(self.filter_config, "thresholds", {})

        spans: List[Span] = []
        for item in ph_eye_spans:
            label = item.get("label", "")
            score = float(item.get("score", 0.0))
            span_text = item.get("text", "")
            start = int(item.get("start", 0))
            end = int(item.get("end", 0))

            if labels and label not in labels:
                continue

            threshold = thresholds.get(label.upper(), 0.0)
            if score < threshold:
                continue

            if span_text in ignored_terms:
                continue

            if label.upper() == "PERSON":
                filter_type = "person"
            else:
                filter_type = label.lower() if label else FilterType.PH_EYE

            replacement = (
                strategy.get_replacement(filter_type, span_text) if strategy else span_text
            )

            spans.append(Span(
                character_start=start,
                character_end=end,
                filter_type=filter_type,
                context=context,
                confidence=score,
                text=span_text,
                replacement=replacement,
                ignored=False,
            ))

        return spans
