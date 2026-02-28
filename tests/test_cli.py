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

"""Tests for the phileas CLI."""

from __future__ import annotations

import json
import os

import pytest

from phileas.cli import main


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_policy(tmp_path, data: dict, ext: str = ".json") -> str:
    """Write *data* as a policy file and return the path."""
    path = tmp_path / f"policy{ext}"
    if ext in (".yaml", ".yml"):
        import yaml
        path.write_text(yaml.dump(data), encoding="utf-8")
    else:
        path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


_EMAIL_POLICY = {
    "name": "test",
    "identifiers": {
        "emailAddress": {
            "emailAddressFilterStrategies": [
                {"strategy": "REDACT", "redactionFormat": "{{{REDACTED-%t}}}"}
            ]
        }
    },
}


# ---------------------------------------------------------------------------
# Basic invocation
# ---------------------------------------------------------------------------

class TestCLIBasic:
    def test_email_redacted_with_text_arg(self, tmp_path, capsys):
        policy_file = _write_policy(tmp_path, _EMAIL_POLICY)
        rc = main(["-p", policy_file, "-c", "ctx", "-t", "Email me at john@example.com."])
        assert rc == 0
        out = capsys.readouterr().out
        assert "john@example.com" not in out
        assert "{{{REDACTED-email-address}}}" in out

    def test_no_pii_text_unchanged(self, tmp_path, capsys):
        policy_file = _write_policy(tmp_path, {"name": "empty"})
        rc = main(["-p", policy_file, "-c", "ctx", "-t", "Nothing sensitive."])
        assert rc == 0
        out = capsys.readouterr().out
        assert out.strip() == "Nothing sensitive."

    def test_yaml_policy_file(self, tmp_path, capsys):
        policy_file = _write_policy(tmp_path, _EMAIL_POLICY, ext=".yaml")
        rc = main(["-p", policy_file, "-c", "ctx", "-t", "Email me at john@example.com."])
        assert rc == 0
        out = capsys.readouterr().out
        assert "john@example.com" not in out

    def test_file_input(self, tmp_path, capsys):
        policy_file = _write_policy(tmp_path, _EMAIL_POLICY)
        input_file = tmp_path / "input.txt"
        input_file.write_text("Contact admin@corp.com for help.", encoding="utf-8")
        rc = main(["-p", policy_file, "-c", "ctx", "-f", str(input_file)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "admin@corp.com" not in out
        assert "{{{REDACTED-email-address}}}" in out

    def test_output_file(self, tmp_path):
        policy_file = _write_policy(tmp_path, _EMAIL_POLICY)
        output_file = tmp_path / "out.txt"
        rc = main([
            "-p", policy_file,
            "-c", "ctx",
            "-t", "Email me at john@example.com.",
            "-o", str(output_file),
        ])
        assert rc == 0
        result = output_file.read_text(encoding="utf-8")
        assert "john@example.com" not in result
        assert "{{{REDACTED-email-address}}}" in result

    def test_custom_document_id(self, tmp_path, capsys):
        policy_file = _write_policy(tmp_path, _EMAIL_POLICY)
        rc = main(["-p", policy_file, "-c", "ctx", "-d", "my-doc", "-t", "plain text"])
        assert rc == 0

    def test_spans_flag_writes_json_to_stderr(self, tmp_path, capsys):
        policy_file = _write_policy(tmp_path, _EMAIL_POLICY)
        rc = main(["-p", policy_file, "-c", "ctx", "-t", "Email john@example.com.", "--spans"])
        assert rc == 0
        err = capsys.readouterr().err
        spans = json.loads(err)
        assert isinstance(spans, list)
        assert len(spans) == 1
        span = spans[0]
        assert span["filterType"] == "email-address"
        assert span["text"] == "john@example.com"

    def test_spans_flag_empty_list_when_no_pii(self, tmp_path, capsys):
        policy_file = _write_policy(tmp_path, {"name": "empty"})
        rc = main(["-p", policy_file, "-c", "ctx", "-t", "No PII here.", "--spans"])
        assert rc == 0
        err = capsys.readouterr().err
        spans = json.loads(err)
        assert spans == []


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestCLIErrors:
    def test_missing_policy_file_exits(self, tmp_path):
        with pytest.raises(SystemExit) as exc_info:
            main(["-p", str(tmp_path / "nonexistent.json"), "-c", "ctx", "-t", "hello"])
        assert exc_info.value.code != 0

    def test_missing_input_file_exits(self, tmp_path):
        policy_file = _write_policy(tmp_path, _EMAIL_POLICY)
        with pytest.raises(SystemExit) as exc_info:
            main(["-p", policy_file, "-c", "ctx", "-f", str(tmp_path / "no_such_file.txt")])
        assert exc_info.value.code != 0

    def test_text_and_file_mutually_exclusive(self, tmp_path):
        policy_file = _write_policy(tmp_path, _EMAIL_POLICY)
        input_file = tmp_path / "input.txt"
        input_file.write_text("hello")
        with pytest.raises(SystemExit) as exc_info:
            main(["-p", policy_file, "-c", "ctx", "-t", "hello", "-f", str(input_file)])
        assert exc_info.value.code != 0

    def test_missing_policy_arg_exits(self, tmp_path):
        with pytest.raises(SystemExit) as exc_info:
            main(["-c", "ctx", "-t", "hello"])
        assert exc_info.value.code != 0

    def test_missing_context_arg_exits(self, tmp_path):
        policy_file = _write_policy(tmp_path, _EMAIL_POLICY)
        with pytest.raises(SystemExit) as exc_info:
            main(["-p", policy_file, "-t", "hello"])
        assert exc_info.value.code != 0

    def test_missing_input_arg_exits(self, tmp_path):
        policy_file = _write_policy(tmp_path, _EMAIL_POLICY)
        with pytest.raises(SystemExit) as exc_info:
            main(["-p", policy_file, "-c", "ctx"])
        assert exc_info.value.code != 0


# ---------------------------------------------------------------------------
# Evaluation (--evaluate) tests
# ---------------------------------------------------------------------------

class TestCLIEvaluate:
    def _write_gt_file(self, tmp_path, spans: list, filename: str = "gt.json") -> str:
        path = tmp_path / filename
        path.write_text(json.dumps(spans), encoding="utf-8")
        return str(path)

    def test_evaluate_perfect_match(self, tmp_path, capsys):
        policy_file = _write_policy(tmp_path, _EMAIL_POLICY)
        # john@example.com is at positions 12..28 in "Email me at john@example.com."
        text = "Email me at john@example.com."
        gt_file = self._write_gt_file(tmp_path, [{"start": 12, "end": 28}])
        rc = main(["-p", policy_file, "-c", "ctx", "-t", text, "--evaluate", gt_file])
        assert rc == 0
        out = capsys.readouterr().out
        # The evaluate output is printed after the filtered text; parse the last JSON block
        metrics = json.loads(out.split("\n", 1)[1])
        assert metrics["truePositives"] == 1
        assert metrics["falsePositives"] == 0
        assert metrics["falseNegatives"] == 0
        assert metrics["f1"] == 1.0

    def test_evaluate_empty_ground_truth_all_fp(self, tmp_path, capsys):
        policy_file = _write_policy(tmp_path, _EMAIL_POLICY)
        gt_file = self._write_gt_file(tmp_path, [])
        rc = main([
            "-p", policy_file, "-c", "ctx",
            "-t", "Email john@example.com here.",
            "--evaluate", gt_file,
        ])
        assert rc == 0
        out = capsys.readouterr().out
        metrics = json.loads(out.split("\n", 1)[1])
        assert metrics["falsePositives"] == 1
        assert metrics["truePositives"] == 0

    def test_evaluate_metrics_keys_present(self, tmp_path, capsys):
        policy_file = _write_policy(tmp_path, _EMAIL_POLICY)
        gt_file = self._write_gt_file(tmp_path, [])
        rc = main(["-p", policy_file, "-c", "ctx", "-t", "plain text", "--evaluate", gt_file])
        assert rc == 0
        out = capsys.readouterr().out
        metrics = json.loads(out.split("\n", 1)[1])
        for key in ("truePositives", "falsePositives", "falseNegatives", "precision", "recall", "f1"):
            assert key in metrics

    def test_evaluate_missing_file_exits(self, tmp_path):
        policy_file = _write_policy(tmp_path, _EMAIL_POLICY)
        with pytest.raises(SystemExit) as exc_info:
            main([
                "-p", policy_file, "-c", "ctx",
                "-t", "hello",
                "--evaluate", str(tmp_path / "nonexistent.json"),
            ])
        assert exc_info.value.code != 0

    def test_evaluate_invalid_json_exits(self, tmp_path):
        policy_file = _write_policy(tmp_path, _EMAIL_POLICY)
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("NOT JSON", encoding="utf-8")
        with pytest.raises(SystemExit) as exc_info:
            main([
                "-p", policy_file, "-c", "ctx",
                "-t", "hello",
                "--evaluate", str(bad_file),
            ])
        assert exc_info.value.code != 0

    def test_evaluate_dict_annotation_format(self, tmp_path, capsys):
        """The dict format {'spans': [...]} is also accepted."""
        policy_file = _write_policy(tmp_path, _EMAIL_POLICY)
        annotation_data = {"text": "Email john@example.com.", "spans": [{"start": 6, "end": 22}]}
        gt_file = tmp_path / "gt.json"
        gt_file.write_text(json.dumps(annotation_data), encoding="utf-8")
        rc = main([
            "-p", policy_file, "-c", "ctx",
            "-t", "Email john@example.com.",
            "--evaluate", str(gt_file),
        ])
        assert rc == 0
        out = capsys.readouterr().out
        metrics = json.loads(out.split("\n", 1)[1])
        assert metrics["truePositives"] == 1
