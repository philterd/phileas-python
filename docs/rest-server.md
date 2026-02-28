# REST Server

phileas includes a built-in HTTP server that exposes the redaction pipeline as a REST API. This makes it easy to integrate phileas into any stack — just send JSON, get JSON back.

## Installation

The server depends on [Flask](https://flask.palletsprojects.com/). Install phileas with the `server` extra to pull it in automatically:

```bash
pip install "phileas[server]"
```

If you are working from a local clone, install in editable mode:

```bash
pip install -e ".[server]"
```

## Starting the server

Once installed, start the server with the `phileas-server` command:

```bash
phileas-server
```

The server listens on `0.0.0.0:8080` by default. You should see output similar to:

```
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:8080
```

> **Note:** `phileas-server` uses Flask's built-in development server, which is suitable for local testing and development. For production deployments, run the app through a production WSGI server such as [Gunicorn](https://gunicorn.org/):
>
> ```bash
> pip install gunicorn
> gunicorn "phileas.server:app" --bind 0.0.0.0:8080
> ```

## Endpoints

### `POST /api/filter`

Filter (redact) text according to a supplied policy.

#### Request

**Content-Type:** `application/json`

| Field | Type | Required | Description |
|---|---|---|---|
| `policy` | object | Yes | A policy object (same schema as [`Policy.from_dict()`](api-reference.md#policyfrom_dictdata)) |
| `text` | string | Yes | The text to redact |
| `context` | string | Yes | An arbitrary context name (e.g. application or user name) |
| `documentId` | string | No | A unique identifier for the document. Auto-generated (UUID) if omitted. |

#### Response

**Content-Type:** `application/json`

| Field | Type | Description |
|---|---|---|
| `filteredText` | string | The input text with sensitive values replaced |
| `context` | string | The context value from the request |
| `documentId` | string | The document ID (supplied or auto-generated) |
| `spans` | array | One object per detected piece of sensitive information (see below) |

Each object in `spans` contains:

| Field | Type | Description |
|---|---|---|
| `characterStart` | integer | Start index (inclusive) of the match in the original text |
| `characterEnd` | integer | End index (exclusive) of the match in the original text |
| `filterType` | string | The type of PII detected (e.g. `"email-address"`, `"ssn"`) |
| `text` | string | The original matched text |
| `replacement` | string | The replacement value applied |
| `confidence` | float | Confidence score (0.0 – 1.0) |
| `ignored` | boolean | `true` if the span was detected but not replaced (matched an ignore rule) |
| `context` | string | The context value from the request |

#### HTTP status codes

| Code | Meaning |
|---|---|
| `200` | Success |
| `400` | Bad request — missing or malformed fields |
| `405` | Method not allowed |

## Examples

### Redact an email address

```bash
curl -s -X POST http://localhost:8080/api/filter \
  -H "Content-Type: application/json" \
  -d '{
    "policy": {
      "name": "default",
      "identifiers": {
        "emailAddress": {}
      }
    },
    "text": "Contact john@example.com for details.",
    "context": "my-app"
  }' | python3 -m json.tool
```

Response:

```json
{
    "context": "my-app",
    "documentId": "a1b2c3d4-...",
    "filteredText": "Contact {{{REDACTED-email-address}}} for details.",
    "spans": [
        {
            "characterEnd": 23,
            "characterStart": 8,
            "confidence": 1.0,
            "context": "my-app",
            "filterType": "email-address",
            "ignored": false,
            "replacement": "{{{REDACTED-email-address}}}",
            "text": "john@example.com"
        }
    ]
}
```

### Redact multiple PII types

```bash
curl -s -X POST http://localhost:8080/api/filter \
  -H "Content-Type: application/json" \
  -d '{
    "policy": {
      "name": "multi",
      "identifiers": {
        "emailAddress": {},
        "phoneNumber": {},
        "ssn": {}
      }
    },
    "text": "Call 800-555-1234 or email bob@example.com. SSN: 123-45-6789.",
    "context": "hr-system",
    "documentId": "doc-001"
  }' | python3 -m json.tool
```

### Use a custom replacement strategy (MASK)

```bash
curl -s -X POST http://localhost:8080/api/filter \
  -H "Content-Type: application/json" \
  -d '{
    "policy": {
      "name": "mask-policy",
      "identifiers": {
        "emailAddress": {
          "emailAddressFilterStrategies": [
            {"strategy": "MASK"}
          ]
        }
      }
    },
    "text": "Reach us at support@example.com.",
    "context": "web"
  }' | python3 -m json.tool
```

### Use a static replacement string

```bash
curl -s -X POST http://localhost:8080/api/filter \
  -H "Content-Type: application/json" \
  -d '{
    "policy": {
      "name": "static-policy",
      "identifiers": {
        "ssn": {
          "ssnFilterStrategies": [
            {"strategy": "STATIC_REPLACE", "staticReplacement": "XXX-XX-XXXX"}
          ]
        }
      }
    },
    "text": "Patient SSN: 123-45-6789.",
    "context": "ehr"
  }' | python3 -m json.tool
```

### Supply a custom document ID

```bash
curl -s -X POST http://localhost:8080/api/filter \
  -H "Content-Type: application/json" \
  -d '{
    "policy": {"name": "default", "identifiers": {"emailAddress": {}}},
    "text": "Send to admin@example.org.",
    "context": "batch-job",
    "documentId": "report-2024-01"
  }' | python3 -m json.tool
```

### Error response example

Sending a request with a missing required field returns HTTP `400`:

```bash
curl -s -X POST http://localhost:8080/api/filter \
  -H "Content-Type: application/json" \
  -d '{"text": "hello"}' | python3 -m json.tool
```

```json
{
    "error": "Missing required fields: policy, context"
}
```
