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

    Config is a ph-eye node from ``identifiers.pheyes``. Settings are read from
    the nested ``phEyeConfiguration`` object (the schema 1.1.0 location), with a
    top-level fallback for hand-written policies.

    When ``modelPath`` is set it points at a **local GLiNER model directory**
    (the ONNX model, its tokenizer, and the GLiNER config), and detection runs
    on-device, matching what the PhiSQL ``DETECT PHEYE ... MODEL '<path>'``
    clause compiles to. Local inference takes precedence over a remote
    ``endpoint`` when both are present. ``labels`` is the GLiNER detection
    prompt, and ``threshold`` (default ``0.5``) is the minimum span confidence.
    """

    DEFAULT_THRESHOLD = 0.5

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
        labels = self._opt("labels", ["PERSON"])

        # A local model directory takes precedence: detection runs on-device and
        # the remote endpoint is not called, even when no endpoint is configured.
        if model_path:
            items = self._predict_local(text, model_path, labels)
        else:
            endpoint = self._opt("endpoint", "")
            if not endpoint:
                return []
            items = self._predict_remote(text, context, endpoint, labels)

        return self._to_spans(items, context, labels)

    def _predict_remote(self, text, context, endpoint, labels) -> list:
        bearer_token = self._opt("bearerToken", "")
        timeout = self._opt("timeout", 30) or 30

        payload = json.dumps({
            "text": text,
            "context": context,
            "piece": 0,
            "labels": list(labels),
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

    def _predict_local(self, text, model_path, labels) -> list:
        """Run on-device GLiNER inference from a local model directory.

        ``model_path`` is a directory holding the exported ONNX model
        (``model.onnx``), its tokenizer, and the GLiNER config, as produced for
        the ``pheye-local-model`` example.
        """
        if self._model is None:
            try:
                from gliner import GLiNER
            except ImportError as exc:
                raise ImportError(
                    "The 'gliner' package is required for local on-device inference. "
                    "Install it with 'pip install gliner' (or the local-inference extra)."
                ) from exc
            self._model = GLiNER.from_pretrained(
                model_path,
                load_onnx_model=True,
                onnx_model_file="model.onnx",
                local_files_only=True,
            )

        # Predict at the lowest cutoff that could let a span through, then apply the
        # precise filtering in _to_spans.
        return self._model.predict_entities(text, list(labels), threshold=self._predict_threshold())

    def _predict_threshold(self) -> float:
        """The lowest confidence cutoff that could let a span through.

        With a per-label ``thresholds`` map, unlisted labels are not filtered, so
        predict at 0.0 and let _to_spans apply the per-label cutoffs. With no map,
        the single ``threshold`` (default 0.5) is the cutoff.
        """
        thresholds = self._opt("thresholds", {}) or {}
        if thresholds:
            return 0.0
        return float(self._opt("threshold", self.DEFAULT_THRESHOLD))

    def _to_spans(self, items: list, context: str, labels) -> List[Span]:
        thresholds = self._opt("thresholds", {}) or {}
        default_threshold = float(self._opt("threshold", self.DEFAULT_THRESHOLD))
        spans: List[Span] = []
        for item in items:
            label = item.get("label", "")
            score = float(item.get("score", 0.0))
            span_text = item.get("text", "")
            start = int(item.get("start", 0))
            end = int(item.get("end", 0))

            if labels and label not in labels:
                continue
            # A per-label ``thresholds`` map (back-compat) is authoritative when
            # present: listed labels use their value, unlisted labels are not
            # filtered (0.0). With no map, the single ``threshold`` (default 0.5)
            # applies to every label.
            min_score = thresholds.get(label.upper(), 0.0) if thresholds else default_threshold
            if score < min_score:
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
