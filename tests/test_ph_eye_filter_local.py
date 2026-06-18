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

"""Local on-device GLiNER inference for the PhEye filter (schema 1.1.0 modelPath).

The model-backed tests are skipped unless PHILEAS_GLINER_MODEL_DIR points at a
local GLiNER model directory (the ONNX model, tokenizer, and GLiNER config, the
layout produced for the pheye-local-model example), so the suite does not bloat
the repo or hard-fail CI when the model is unavailable.
"""

import os

import pytest

from phileas.filters.ph_eye_filter import PhEyeFilter

MODEL_DIR = os.environ.get("PHILEAS_GLINER_MODEL_DIR")
_HAVE_MODEL = bool(MODEL_DIR) and os.path.isdir(MODEL_DIR)
_SKIP_REASON = (
    "Set PHILEAS_GLINER_MODEL_DIR to a local GLiNER model directory to run "
    "local-inference tests."
)

TEXT = "Please contact Maria Gonzalez or Toni Levine about the invoice."


def test_no_model_and_no_endpoint_returns_no_spans():
    # No modelPath and no endpoint: nothing to call, no detections.
    assert PhEyeFilter({"phEyeConfiguration": {"labels": ["name"]}}).detect(TEXT, "ctx") == []


def test_model_path_takes_precedence_over_endpoint(monkeypatch):
    # When both modelPath and endpoint are set, detection runs locally and the
    # remote endpoint is never called.
    f = PhEyeFilter(
        {"phEyeConfiguration": {"modelPath": "/m", "endpoint": "http://example.invalid", "labels": ["name"]}}
    )
    called = {}

    def fake_local(*args, **kwargs):
        called["local"] = True
        return []

    def fake_remote(*args, **kwargs):
        called["remote"] = True
        return []

    monkeypatch.setattr(f, "_predict_local", fake_local)
    monkeypatch.setattr(f, "_predict_remote", fake_remote)
    f.detect(TEXT, "ctx")
    assert called.get("local") is True
    assert called.get("remote") is None


@pytest.mark.skipif(not _HAVE_MODEL, reason=_SKIP_REASON)
def test_local_inference_from_model_directory():
    pytest.importorskip("gliner")
    cfg = {"phEyeConfiguration": {"modelPath": MODEL_DIR, "labels": ["name"], "threshold": 0.5}}
    spans = PhEyeFilter(cfg).detect(TEXT, "ctx")

    assert spans, "expected at least one detected span from the local model"
    assert all(s.filter_type == "name" for s in spans)
    # Every span slices back to the source text at its offsets.
    for s in spans:
        assert TEXT[s.character_start:s.character_end] == s.text


@pytest.mark.skipif(not _HAVE_MODEL, reason=_SKIP_REASON)
def test_local_inference_threshold_filters():
    pytest.importorskip("gliner")
    low = PhEyeFilter(
        {"phEyeConfiguration": {"modelPath": MODEL_DIR, "labels": ["name"], "threshold": 0.5}}
    ).detect(TEXT, "ctx")
    high = PhEyeFilter(
        {"phEyeConfiguration": {"modelPath": MODEL_DIR, "labels": ["name"], "threshold": 0.999999}}
    ).detect(TEXT, "ctx")

    assert low, "low threshold should return spans"
    assert len(high) < len(low), "a near-1.0 threshold should drop low-confidence spans"
