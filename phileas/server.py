"""Flask server that exposes redaction as a REST endpoint."""

from __future__ import annotations

import uuid

from flask import Flask, request, jsonify

from phileas.policy.policy import Policy
from phileas.services.filter_service import FilterService

app = Flask(__name__)
_filter_service = FilterService()


@app.route("/api/filter", methods=["POST"])
def filter_text():
    """Filter (redact) text according to the provided policy.

    Expected JSON body::

        {
            "policy": { ... },   // policy object (same schema as Policy.from_dict)
            "text": "...",       // text to redact
            "context": "..."     // context name
        }

    Returns a JSON object with the filtered text and span metadata.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    missing = [f for f in ("policy", "text", "context") if f not in data]
    if missing:
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400

    try:
        policy = Policy.from_dict(data["policy"])
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        return jsonify({"error": f"Invalid policy: {exc}"}), 400

    text = data["text"]
    context = data["context"]
    document_id = data.get("documentId", str(uuid.uuid4()))

    result = _filter_service.filter(policy, context, document_id, text)

    return jsonify({
        "filteredText": result.filtered_text,
        "context": result.context,
        "documentId": result.document_id,
        "spans": [
            {
                "characterStart": s.character_start,
                "characterEnd": s.character_end,
                "filterType": s.filter_type,
                "context": s.context,
                "confidence": s.confidence,
                "text": s.text,
                "replacement": s.replacement,
                "ignored": s.ignored,
            }
            for s in result.spans
        ],
    })


def main():
    """Run the development server. For production use a WSGI server such as Gunicorn."""
    app.run(host="0.0.0.0", port=8080)


if __name__ == "__main__":
    main()
