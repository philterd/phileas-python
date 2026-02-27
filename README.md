# phileas-python

A Python port of [Phileas](https://github.com/philterd/phileas) — a library to deidentify and redact PII, PHI, and other sensitive information from text.

## Overview

Phileas analyzes text searching for sensitive information such as email addresses, phone numbers, SSNs, credit card numbers, and many other types of PII/PHI. When sensitive information is identified, Phileas can manipulate it in a variety of ways: the information can be redacted, masked, hashed, or replaced with a static value. The user defines how to handle each type of sensitive information through **policies**.

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
import json
from phileas.policy.policy import Policy
from phileas.services.filter_service import FilterService

# Define a policy as a Python dict (or load from JSON)
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

## Policies

A **policy** is a JSON (or Python dict) object that defines what sensitive information to identify and how to handle it.

### Policy Structure

```json
{
  "name": "my-policy",
  "identifiers": {
    "emailAddress": {
      "enabled": true,
      "emailAddressFilterStrategies": [
        {
          "strategy": "REDACT",
          "redactionFormat": "{{{REDACTED-%t}}}"
        }
      ],
      "ignored": ["noreply@example.com"]
    }
  },
  "ignored": ["safe-term"],
  "ignoredPatterns": ["\\d{3}-test-\\d{4}"]
}
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

```json
{
  "strategy": "REDACT",
  "redactionFormat": "{{{REDACTED-%t}}}",
  "staticReplacement": "[REMOVED]",
  "maskCharacter": "*",
  "maskLength": "SAME",
  "truncateLeaveCharacters": 4,
  "truncateDirection": "LEADING",
  "condition": ""
}
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

## API Reference

### `FilterService`

```python
from phileas.services.filter_service import FilterService

service = FilterService()
result = service.filter(policy, context, document_id, text)
```

#### Parameters

| Parameter | Type | Description |
|---|---|---|
| `policy` | `Policy` | The policy to apply |
| `context` | `str` | An identifier for the request context (e.g., user or application name) |
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

## Running Tests

```bash
pytest tests/ -v
```

## License

Copyright 2025 Philterd, LLC.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

This project is a Python port of [Phileas](https://github.com/philterd/phileas), which is also Apache-2.0 licensed.