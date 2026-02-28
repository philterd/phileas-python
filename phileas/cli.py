"""Command-line interface for phileas redaction."""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid

import yaml

from phileas.policy.policy import Policy
from phileas.services.filter_service import FilterService
from phileas.services.evaluation_service import EvaluationService


def _load_policy(policy_path: str) -> Policy:
    """Load a policy from a JSON or YAML file."""
    _, ext = os.path.splitext(policy_path.lower())
    with open(policy_path, "r", encoding="utf-8") as fh:
        content = fh.read()
    if ext in (".yaml", ".yml"):
        return Policy.from_yaml(content)
    return Policy.from_json(content)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phileas",
        description="Redact sensitive information from text using a phileas policy.",
    )
    parser.add_argument(
        "-p", "--policy",
        required=True,
        metavar="FILE",
        help="Path to a policy file (JSON or YAML).",
    )
    parser.add_argument(
        "-c", "--context",
        required=True,
        metavar="CONTEXT",
        help="Context name used for referential integrity across documents.",
    )
    parser.add_argument(
        "-d", "--document-id",
        default=None,
        metavar="ID",
        dest="document_id",
        help="Optional document identifier. Auto-generated if omitted.",
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "-t", "--text",
        metavar="TEXT",
        help="Text to redact, supplied directly as a string.",
    )
    input_group.add_argument(
        "-f", "--file",
        metavar="FILE",
        help="Path to a file whose contents should be redacted.",
    )

    parser.add_argument(
        "-o", "--output",
        default=None,
        metavar="FILE",
        help="Write the redacted text to FILE instead of stdout.",
    )
    parser.add_argument(
        "--spans",
        action="store_true",
        default=False,
        help="Print span metadata as JSON to stderr after filtering.",
    )
    parser.add_argument(
        "--evaluate",
        metavar="FILE",
        default=None,
        dest="evaluate",
        help=(
            "Path to a LAPPS JSON file containing ground-truth spans. "
            "When provided, phileas runs the filter, compares detected spans "
            "against the ground-truth annotations, and prints evaluation "
            "metrics (precision, recall, F1) to stdout."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``phileas`` CLI command."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Load policy
    try:
        policy = _load_policy(args.policy)
    except FileNotFoundError:
        parser.error(f"Policy file not found: {args.policy}")
    except json.JSONDecodeError as exc:
        parser.error(f"Failed to parse policy file '{args.policy}' as JSON: {exc}")
    except yaml.YAMLError as exc:
        parser.error(f"Failed to parse policy file '{args.policy}' as YAML: {exc}")
    except (ValueError, KeyError, TypeError) as exc:
        parser.error(f"Invalid policy in '{args.policy}': {exc}")

    # Load input text
    if args.file is not None:
        try:
            with open(args.file, "r", encoding="utf-8") as fh:
                text = fh.read()
        except FileNotFoundError:
            parser.error(f"Input file not found: {args.file}")
        except OSError as exc:
            parser.error(f"Failed to read input file '{args.file}': {exc}")
    else:
        text = args.text

    document_id = args.document_id or str(uuid.uuid4())

    service = FilterService()
    result = service.filter(policy, args.context, document_id, text)

    # Write filtered text
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(result.filtered_text)
        except OSError as exc:
            sys.stderr.write(f"Error writing output file '{args.output}': {exc}\n")
            return 1
    else:
        print(result.filtered_text)

    # Optionally print spans as JSON to stderr
    if args.spans:
        spans_data = [
            {
                "characterStart": s.character_start,
                "characterEnd": s.character_end,
                "filterType": s.filter_type,
                "text": s.text,
                "replacement": s.replacement,
                "confidence": s.confidence,
                "ignored": s.ignored,
                "context": s.context,
            }
            for s in result.spans
        ]
        sys.stderr.write(json.dumps(spans_data, indent=2) + "\n")

    # Optionally run evaluation against a LAPPS JSON ground-truth file
    if args.evaluate:
        try:
            with open(args.evaluate, "r", encoding="utf-8") as fh:
                lapps_data = json.load(fh)
        except FileNotFoundError:
            parser.error(f"LAPPS ground-truth file not found: {args.evaluate}")
        except json.JSONDecodeError as exc:
            parser.error(f"Failed to parse LAPPS file '{args.evaluate}' as JSON: {exc}")
        except OSError as exc:
            parser.error(f"Failed to read LAPPS file '{args.evaluate}': {exc}")

        try:
            eval_svc = EvaluationService()
            eval_result = eval_svc.evaluate(policy, args.context, document_id, text, lapps_data)
        except (ValueError, KeyError, TypeError) as exc:
            parser.error(f"Invalid LAPPS data in '{args.evaluate}': {exc}")

        metrics = {
            "truePositives": eval_result.true_positives,
            "falsePositives": eval_result.false_positives,
            "falseNegatives": eval_result.false_negatives,
            "precision": eval_result.precision,
            "recall": eval_result.recall,
            "f1": eval_result.f1,
        }
        print(json.dumps(metrics, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
