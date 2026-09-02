# Phileas

A library to deidentify and redact PII, PHI, and other sensitive information from text.

### 📖 [Read the documentation →](https://philterd.github.io/phileas-python/)

* Full guides, code examples, and the API reference live on the [documentation website](https://philterd.github.io/phileas-python/).
* Built by [Philterd](https://www.philterd.ai).
* Commercial support and consulting is available - [contact us](https://www.philterd.ai).

## Overview

Phileas analyzes text searching for sensitive information such as email addresses, phone numbers, SSNs, credit card numbers, and many other types of PII/PHI. When sensitive information is identified, Phileas can manipulate it in a variety of ways: the information can be redacted, masked, hashed, or replaced with a static value. The user defines how to handle each type of sensitive information through policies (YAML or JSON).

Other capabilities include referential integrity for redactions, conditional logic for redactions, and a CLI.

Phileas requires no machine-learning dependencies (e.g. no ChatGPT/etc.) and is intended to be lightweight and easy to use.

## Installation

```bash
pip install phileas-redact
```

This pulls in the [`phisql`](https://github.com/philterd/phisql) package, which supplies the catalog of redaction strategies and policy field names.

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

## Documentation

| Guide | |
|---|---|
| [Installation](https://philterd.github.io/phileas-python/installation/) | Requirements and installing from source |
| [Quick start](https://philterd.github.io/phileas-python/quickstart/) | A first filter, step by step |
| [Policies](https://philterd.github.io/phileas-python/policies/) | Policy structure, strategies, conditions, ignored terms |
| [Filters](https://philterd.github.io/phileas-python/filters/) | Every supported type of sensitive information and its options |
| [Examples](https://philterd.github.io/phileas-python/examples/) | Recipes for common tasks |
| [CLI](https://philterd.github.io/phileas-python/cli/) | Redacting files from the command line, and evaluation mode |
| [API reference](https://philterd.github.io/phileas-python/api-reference/) | `FilterService`, `Policy`, `Span`, and the context services |

## Development

```bash
git clone https://github.com/philterd/phileas-python.git
cd phileas-python
pip install -e ".[dev]"
pytest tests/
```

## License

Copyright 2026 Philterd, LLC.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

"Phileas" and "Philter" are registered trademarks of Philterd, LLC.
