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

"""End-to-end test against the published philterd/ph-eye-pii-en-xsmall model.

It downloads the model from Hugging Face (the int8 ONNX graph, the tokenizer, and the
GLiNER config), runs real local inference through PhEyeFilter, and asserts the model
identifies "George Washington". This exercises the full on-device path against real
weights, complementing test_ph_eye_filter_local.py (which uses an out-of-band model dir).

It is opt-in: it runs only when PHILEAS_DOWNLOAD_MODEL=1 is set, so the default suite
stays offline. Downloaded files are cached under the temp directory.
"""

import os
import shutil
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

import pytest

BASE_URL = "https://huggingface.co/philterd/ph-eye-pii-en-xsmall/resolve/main/"
TEXT = "George Washington was the first president of the United States."

# (local name in the model dir, remote path under the repo, required?)
# model.onnx lives under onnx/ in the repo but the loader expects it at the top of the dir.
_FILES = [
    ("model.onnx", "onnx/model.onnx", True),
    ("tokenizer.json", "tokenizer.json", True),
    ("gliner_config.json", "gliner_config.json", True),
    ("tokenizer_config.json", "tokenizer_config.json", False),
    ("special_tokens_map.json", "special_tokens_map.json", False),
    ("added_tokens.json", "added_tokens.json", False),
]

_SKIP_REASON = (
    "Set PHILEAS_DOWNLOAD_MODEL=1 to run the end-to-end test that downloads "
    "ph-eye-pii-en-xsmall from Hugging Face (~90 MB) and runs local inference."
)


def _ensure_downloaded() -> str:
    model_dir = Path(tempfile.gettempdir()) / "phileas-ph-eye-pii-en-xsmall-py"
    model_dir.mkdir(parents=True, exist_ok=True)
    for local, remote, required in _FILES:
        dest = model_dir / local
        if dest.exists() and dest.stat().st_size > 0:
            continue
        try:
            with urllib.request.urlopen(BASE_URL + remote, timeout=300) as response, open(dest, "wb") as out:
                shutil.copyfileobj(response, out)
        except urllib.error.HTTPError as exc:
            if required:
                raise
            # Optional tokenizer artifact not present in this repo; ignore.
            if dest.exists():
                dest.unlink()
    return str(model_dir)


@pytest.mark.skipif(os.environ.get("PHILEAS_DOWNLOAD_MODEL") != "1", reason=_SKIP_REASON)
def test_detects_george_washington():
    pytest.importorskip("gliner")
    from phileas.filters.ph_eye_filter import PhEyeFilter

    model_dir = _ensure_downloaded()
    cfg = {"phEyeConfiguration": {"modelPath": model_dir, "labels": ["name"], "threshold": 0.5}}
    spans = PhEyeFilter(cfg).detect(TEXT, "ctx")

    assert spans, "expected at least one detected span"

    # The model may return one full-name span or separate first/last spans, so assert that every
    # non-space character of "George Washington" is covered by some detected span.
    start = TEXT.index("George Washington")
    end = start + len("George Washington")
    for i in range(start, end):
        if TEXT[i] == " ":
            continue
        assert any(s.character_start <= i < s.character_end for s in spans), (
            f"'George Washington' not fully covered; spans: "
            f"{[(s.text, s.character_start, s.character_end) for s in spans]}"
        )
