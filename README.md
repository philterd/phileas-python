# Phileas (python)

A Python port of [Phileas (Java)](https://github.com/philterd/phileas) — a library to deidentify and redact PII, PHI, and other sensitive information from text.

* Check out the [documentation](https://philterd.github.io/phileas-python/) or details and code examples.
* Built by [Philterd](https://www.philterd.ai).
* Commercial support and consulting is available - [contact us](https://www.philterd.ai).

## Overview

Phileas analyzes text searching for sensitive information such as email addresses, phone numbers, SSNs, credit card numbers, and many other types of PII/PHI. When sensitive information is identified, Phileas can manipulate it in a variety of ways: the information can be redacted, masked, hashed, or replaced with a static value. The user defines how to handle each type of sensitive information through **policies**. Other capabilities include referential integrity for redactions, conditional logic for redactions, and a CLI.

## Compatibility Notes

Note that this port of [Phileas](https://github.com/philterd/phileas) is not 1:1 with the Java version. There are some differences:

* This project includes a server that exposes redaction HTTP endpoints. For the Java version, the API server is [Philter](https://github.com/philterd/philter).
* This project includes support for policies in YAML as well as JSON.
* This project does not include all redaction strategies present in the Java version.
* This project includes a CLI.
* This project includes the ability to evaluate performance using precision and recall through a built-in evaluation tool.
* This project does not include support for PDF documents which is present in the Java version.

## Installation

```bash
pip install phileas
```

Or, to install in development mode from source:

```bash
git clone https://github.com/philterd/phileas-python.git
cd phileas-python
pip install -e ".[dev]"
```

## Quick Start

```python
from phileas.policy.policy import Policy
from phileas.services.filter_service import FilterService

# Define a policy as a Python dict (or load from YAML)
policy_dict = {
    "name": "my-policy",
    "identifiers": {
        "emailAddress": {
            "emailAddressFilterStrategies": [{
                "strategy": "REDACT",
                "redactionFormat": "{{{REDACTED-%t}}}"
            }]
        },
        "ssn": {
            "ssnFilterStrategies": [{
                "strategy": "REDACT",
                "redactionFormat": "{{{REDACTED-%t}}}"
            }]
        }
    }
}

policy = Policy.from_dict(policy_dict)
service = FilterService()

result = service.filter(
    policy=policy,
    context="my-context",
    document_id="doc-001",
    text="Contact john@example.com or call about SSN 123-45-6789."
)

print(result.filtered_text)
# Contact {{{REDACTED-email-address}}} or call about SSN {{{REDACTED-ssn}}}.

for span in result.spans:
    print(f"  [{span.filter_type}] '{span.text}' -> '{span.replacement}' at {span.character_start}:{span.character_end}")
```

## Supported PII / PHI Types

| Policy Key | Filter Type | Description |
|---|---|---|
| `age` | `age` | Age references (e.g., "35 years old", "aged 25") |
| `emailAddress` | `email-address` | Email addresses |
| `creditCard` | `credit-card` | Credit card numbers (Visa, MC, AmEx, Discover, etc.) |
| `ssn` | `ssn` | Social Security Numbers (SSNs) and TINs |
| `phoneNumber` | `phone-number` | US phone numbers |
| `ipAddress` | `ip-address` | IPv4 and IPv6 addresses |
| `url` | `url` | HTTP/HTTPS URLs |
| `zipCode` | `zip-code` | US ZIP codes (5-digit and ZIP+4) |
| `vin` | `vin` | Vehicle Identification Numbers |
| `bitcoinAddress` | `bitcoin-address` | Bitcoin addresses |
| `bankRoutingNumber` | `bank-routing-number` | US ABA bank routing numbers |
| `date` | `date` | Dates in common formats |
| `macAddress` | `mac-address` | Network MAC addresses |
| `currency` | `currency` | USD currency amounts |
| `streetAddress` | `street-address` | US street addresses |
| `trackingNumber` | `tracking-number` | UPS, FedEx, and USPS tracking numbers |
| `driversLicense` | `drivers-license` | US driver's license numbers |
| `ibanCode` | `iban-code` | International Bank Account Numbers (IBANs) |
| `passportNumber` | `passport-number` | US passport numbers |
| `patterns` | user-defined | Custom regex-based patterns (list of pattern filters) |

## Policies

A **policy** is a YAML (or Python dict) object that defines what sensitive information to identify and how to handle it.

### Policy Structure

```yaml
name: my-policy
identifiers:
  emailAddress:
    enabled: true
    emailAddressFilterStrategies:
      - strategy: REDACT
        redactionFormat: "{{{REDACTED-%t}}}"
    ignored:
      - noreply@example.com
ignored:
  - safe-term
ignoredPatterns:
  - "\\d{3}-test-\\d{4}"
```

### Filter Strategies

Each filter type supports one or more strategies that define what to do with the identified information:

| Strategy | Description | Example Output |
|---|---|---|
| `REDACT` | Replace with a redaction tag | `{{{REDACTED-email-address}}}` |
| `MASK` | Replace each character with `*` | `***@*******.***` |
| `STATIC_REPLACE` | Replace with a fixed string | `[REMOVED]` |
| `HASH_SHA256_REPLACE` | Replace with the SHA-256 hash | `a665a4592...` |
| `LAST_4` | Mask all but the last 4 characters | `****6789` |
| `SAME` | Leave the value unchanged (identify only) | `123-45-6789` |
| `TRUNCATE` | Keep leading or trailing characters | `john@***` |
| `ABBREVIATE` | Abbreviate the value | `J. S.` |

### Strategy Options

```yaml
strategy: REDACT
redactionFormat: "{{{REDACTED-%t}}}"
staticReplacement: "[REMOVED]"
maskCharacter: "*"
maskLength: SAME
truncateLeaveCharacters: 4
truncateDirection: LEADING
condition: ""
```

- `%t` in `redactionFormat` is replaced by the filter type name.

### Ignored Terms

You can specify terms that should never be redacted at the policy level or per-filter level:

```python
policy_dict = {
    "name": "my-policy",
    "identifiers": {
        "emailAddress": {
            "emailAddressFilterStrategies": [{"strategy": "REDACT"}],
            "ignored": ["noreply@internal.com"]
        }
    },
    "ignored": ["safe-global-term"],
    "ignoredPatterns": ["\\d{3}-555-\\d{4}"]
}
```

### Pattern-Based Filters

A policy can include a list of custom regex-based filters. Each pattern filter specifies a `pattern` (a regular expression) and an optional `label` used as the filter type in results. This is useful for identifying domain-specific PII that is not covered by the built-in filters.

```python
policy_dict = {
    "name": "my-policy",
    "identifiers": {
        "patterns": [
            {
                "pattern": "\\d{3}-\\d{3}-\\d{3}",
                "label": "custom-id",
                "patternFilterStrategies": [{"strategy": "REDACT"}]
            }
        ]
    }
}

policy = Policy.from_dict(policy_dict)
result = service.filter(policy, "ctx", "doc1", "ID: 123-456-789")
print(result.filtered_text)  # ID: {{{REDACTED-custom-id}}}
```

Multiple pattern filters can be included in the same policy:

```python
"patterns": [
    {"pattern": "\\d{3}-\\d{3}-\\d{3}", "label": "id-number"},
    {"pattern": "[A-Z]{2}\\d{6}", "label": "passport-number"}
]
```

#### Pattern Filter Options

| Field | Type | Description |
|---|---|---|
| `pattern` | `str` | Regular expression used to identify PII |
| `label` | `str` | Filter type label used in spans (defaults to `"pattern"`) |
| `patternFilterStrategies` | `list` | List of filter strategies (same as other filter types) |
| `ignored` | `list` | Terms that should not be redacted even if they match |
| `enabled` | `bool` | Whether the filter is active (default: `true`) |

## Contexts and Referential Integrity

Every call to `FilterService.filter()` takes a **context** name. The context is a logical grouping that ties multiple documents together — for example, all documents belonging to a single patient, user, or case.

Phileas uses the context to maintain **referential integrity**: once a PII token has been replaced, every subsequent occurrence of that same token in the same context receives the *identical* replacement. This ensures that redacted documents within a context remain internally consistent and can still be cross-referenced without revealing the underlying sensitive values.

### How it works

Phileas maintains a `ContextService` — a map of maps with the structure:

```
context_name → { token → replacement }
```

Before applying any replacement, `FilterService` checks whether the token already has a stored replacement for the current context:

- **Token found** — the stored replacement is used instead of generating a new one.
- **Token not found** — the newly generated replacement is stored and then applied.

The default implementation is `InMemoryContextService`, which stores mappings in memory for the lifetime of the `FilterService` instance.

### Using the default in-memory context service

```python
from phileas import FilterService

service = FilterService()  # uses InMemoryContextService automatically

# Both calls operate in the same context, so 555-123-4567 always gets
# the same replacement across documents.
result1 = service.filter(policy, "patient-records", "doc1", "Call 555-123-4567 for info.")
result2 = service.filter(policy, "patient-records", "doc2", "Patient called 555-123-4567 back.")
```

### Pre-seeding the context service

You can pre-populate the context service before filtering to force specific replacements:

```python
from phileas import FilterService, InMemoryContextService

ctx_svc = InMemoryContextService()
ctx_svc.put("patient-records", "john@example.com", "EMAIL-001")

service = FilterService(context_service=ctx_svc)
# john@example.com will always be replaced with EMAIL-001 in the "patient-records" context
```

### Providing a custom context service

Subclass `AbstractContextService` to integrate any external store (e.g. Redis, a database):

```python
from phileas import FilterService, AbstractContextService

class RedisContextService(AbstractContextService):
    def put(self, context: str, token: str, replacement: str) -> None:
        # store in Redis
        ...

    def get(self, context: str, token: str) -> str | None:
        # retrieve from Redis, return None if not found
        ...

    def contains(self, context: str, token: str) -> bool:
        # check existence in Redis
        ...

service = FilterService(context_service=RedisContextService())
```

## API Reference

### `FilterService`

```python
from phileas.services.filter_service import FilterService

service = FilterService(context_service=None)
result = service.filter(policy, context, document_id, text)
```

#### Constructor Parameters

| Parameter | Type | Description |
|---|---|---|
| `context_service` | `AbstractContextService \| None` | Context service implementation to use for referential integrity. Defaults to `InMemoryContextService` when `None`. |

#### `filter()` Parameters

| Parameter | Type | Description |
|---|---|---|
| `policy` | `Policy` | The policy to apply |
| `context` | `str` | Named context that groups documents for referential integrity (e.g., a patient ID or session name) |
| `document_id` | `str` | A unique identifier for the document being filtered |
| `text` | `str` | The text to filter |

#### Returns `FilterResult`

| Attribute | Type | Description |
|---|---|---|
| `filtered_text` | `str` | The text with sensitive information replaced |
| `spans` | `List[Span]` | Metadata about each identified piece of sensitive information |
| `context` | `str` | The context passed to `filter()` |
| `document_id` | `str` | The document ID passed to `filter()` |

### `Span`

| Attribute | Type | Description |
|---|---|---|
| `character_start` | `int` | Start index of the span in the original text |
| `character_end` | `int` | End index of the span in the original text |
| `filter_type` | `str` | The type of PII identified (e.g., `"email-address"`) |
| `text` | `str` | The original text of the span |
| `replacement` | `str` | The replacement value |
| `confidence` | `float` | Confidence score (0.0–1.0) |
| `ignored` | `bool` | Whether this span was marked as ignored (not replaced) |
| `context` | `str` | The context |

### `Policy`

```python
from phileas.policy.policy import Policy

# From a dict
policy = Policy.from_dict({"name": "default", "identifiers": {...}})

# From a JSON string
policy = Policy.from_json('{"name": "default", ...}')

# To JSON
json_str = policy.to_json()

# To dict
d = policy.to_dict()
```

### `AbstractContextService`

Abstract base class for context service implementations. Subclass this to provide a custom backend.

```python
from phileas import AbstractContextService

class MyContextService(AbstractContextService):
    def put(self, context: str, token: str, replacement: str) -> None: ...
    def get(self, context: str, token: str) -> str | None: ...
    def contains(self, context: str, token: str) -> bool: ...
```

#### Methods

| Method | Signature | Description |
|---|---|---|
| `put` | `(context, token, replacement) -> None` | Store a replacement value for a token under the given context |
| `get` | `(context, token) -> str \| None` | Return the stored replacement, or `None` if not found |
| `contains` | `(context, token) -> bool` | Return `True` if a replacement exists for the token in the given context |

### `InMemoryContextService`

Default implementation of `AbstractContextService` backed by a `dict[str, dict[str, str]]`. Suitable for single-process, in-memory use.

```python
from phileas import InMemoryContextService

ctx_svc = InMemoryContextService()
ctx_svc.put("my-context", "john@example.com", "EMAIL-001")
ctx_svc.get("my-context", "john@example.com")      # "EMAIL-001"
ctx_svc.contains("my-context", "john@example.com") # True
```

## Examples

### Mask credit card numbers

```python
policy_dict = {
    "name": "cc-mask",
    "identifiers": {
        "creditCard": {
            "creditCardFilterStrategies": [{"strategy": "LAST_4"}]
        }
    }
}
policy = Policy.from_dict(policy_dict)
result = service.filter(policy, "ctx", "doc1", "Card: 4111111111111111")
print(result.filtered_text)  # Card: ************1111
```

### Hash SSNs

```python
policy_dict = {
    "name": "ssn-hash",
    "identifiers": {
        "ssn": {
            "ssnFilterStrategies": [{"strategy": "HASH_SHA256_REPLACE"}]
        }
    }
}
```

### Disable a filter

```python
policy_dict = {
    "name": "no-url",
    "identifiers": {
        "url": {"enabled": False}
    }
}
```

## CLI

phileas ships a `phileas` command that performs redaction directly from the terminal.

### Usage

```
phileas -p POLICY_FILE -c CONTEXT (-t TEXT | -f FILE) [options]
```

| Argument | Description |
|---|---|
| `-p / --policy FILE` | Path to a policy file (JSON or YAML). |
| `-c / --context CONTEXT` | Context name for referential integrity. |
| `-t / --text TEXT` | Text to redact (mutually exclusive with `--file`). |
| `-f / --file FILE` | Path to a file to redact (mutually exclusive with `--text`). |
| `-d / --document-id ID` | Optional document identifier (auto-generated if omitted). |
| `-o / --output FILE` | Write redacted text to a file instead of stdout. |
| `--spans` | Print span metadata as JSON to stderr. |
| `--evaluate FILE` | Evaluate redaction quality against a JSON ground-truth file. Prints precision, recall, and F1 metrics to stdout. |

### Examples

Redact a string:

```bash
phileas -p policy.yaml -c my-context -t "Contact john@example.com or call 800-555-1234."
# Contact {{{REDACTED-email-address}}} or call {{{REDACTED-phone-number}}}.
```

Redact a file and write output to a new file:

```bash
phileas -p policy.yaml -c my-context -f report.txt -o report_redacted.txt
```

View span metadata for each detected item:

```bash
phileas -p policy.yaml -c my-context -t "Email john@example.com." --spans
```

### Evaluation Mode

Use `--evaluate FILE` to measure the redaction quality of a policy against a set of ground-truth annotations. Phileas runs the filter on the input text, compares the detected spans against the ground-truth spans, and prints precision, recall, and F1 metrics to stdout.

```bash
phileas -p policy.json -c my-context -t "Email john@example.com." --evaluate gt.json
```

The ground-truth file must be a JSON array of span objects, or a JSON object with a `"spans"` key. Each span must have `"start"` and `"end"` character positions; `"type"` is optional:

```json
[{"start": 6, "end": 22, "type": "email-address"}]
```

**Example output:**

```
Email {{{REDACTED-email-address}}}.
{
  "truePositives": 1,
  "falsePositives": 0,
  "falseNegatives": 0,
  "precision": 1.0,
  "recall": 1.0,
  "f1": 1.0
}
```

## Running Tests

```bash
pytest tests/ -v
```

## License

Copyright 2026 Philterd, LLC.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

This project is a Python port of [Phileas](https://github.com/philterd/phileas), which is also Apache-2.0 licensed.