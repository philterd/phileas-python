# Examples

The following examples demonstrate common use cases. All examples assume you have phileas-python installed:

```bash
pip install phileas
```

---

## Redact email addresses

```python
from phileas.policy.policy import Policy
from phileas.services.filter_service import FilterService

policy = Policy.from_dict({
    "name": "email-redact",
    "identifiers": {
        "emailAddress": {
            "emailAddressFilterStrategies": [{"strategy": "REDACT"}]
        }
    }
})

service = FilterService()
result = service.filter(
    policy, "app", "doc-1",
    "Please contact john.doe@example.com or support@company.org for help."
)
print(result.filtered_text)
# Please contact {{{REDACTED-email-address}}} or {{{REDACTED-email-address}}} for help.
```

---

## Mask credit card numbers (show last 4 digits)

```python
policy = Policy.from_dict({
    "name": "cc-last4",
    "identifiers": {
        "creditCard": {
            "creditCardFilterStrategies": [{"strategy": "LAST_4"}]
        }
    }
})

result = service.filter(policy, "app", "doc-2", "Charged to card 4111 1111 1111 1111.")
print(result.filtered_text)
# Charged to card ************1111.
```

---

## Hash Social Security Numbers

Replace an SSN with its SHA-256 hash to maintain referential consistency without exposing the value.

```python
policy = Policy.from_dict({
    "name": "ssn-hash",
    "identifiers": {
        "ssn": {
            "ssnFilterStrategies": [{"strategy": "HASH_SHA256_REPLACE"}]
        }
    }
})

result = service.filter(policy, "app", "doc-3", "SSN: 123-45-6789")
print(result.filtered_text)
# SSN: 01a54629efb952287e554eb23ef69c52097a75aecc0e3a93ca0855ab6d7a31a0
```

---

## Use a custom redaction format

The `%t` placeholder in `redactionFormat` is replaced with the filter type name.

```python
policy = Policy.from_dict({
    "name": "custom-format",
    "identifiers": {
        "phoneNumber": {
            "phoneNumberFilterStrategies": [
                {"strategy": "REDACT", "redactionFormat": "[PHONE-REDACTED]"}
            ]
        }
    }
})

result = service.filter(policy, "app", "doc-4", "Call me at 555-867-5309.")
print(result.filtered_text)
# Call me at [PHONE-REDACTED].
```

---

## Replace with a static value

```python
policy = Policy.from_dict({
    "name": "static-ip",
    "identifiers": {
        "ipAddress": {
            "ipAddressFilterStrategies": [
                {"strategy": "STATIC_REPLACE", "staticReplacement": "0.0.0.0"}
            ]
        }
    }
})

result = service.filter(policy, "app", "doc-5", "Server at 10.0.0.42 is down.")
print(result.filtered_text)
# Server at 0.0.0.0 is down.
```

---

## Shift a date forward

Move detected dates forward by 2 years and 15 days for de-identification.

```python
policy = Policy.from_dict({
    "name": "date-shift",
    "identifiers": {
        "date": {
            "dateFilterStrategies": [
                {"strategy": "SHIFT_DATE", "shiftYears": 2, "shiftDays": 15}
            ]
        }
    }
})

result = service.filter(policy, "app", "doc-6", "Born on 01/15/1990.")
print(result.filtered_text)
# Born on 01/30/1992.
```

---

## Filter multiple PII types at once

```python
policy = Policy.from_dict({
    "name": "multi",
    "identifiers": {
        "emailAddress": {
            "emailAddressFilterStrategies": [{"strategy": "REDACT"}]
        },
        "ssn": {
            "ssnFilterStrategies": [{"strategy": "REDACT"}]
        },
        "phoneNumber": {
            "phoneNumberFilterStrategies": [{"strategy": "MASK"}]
        },
        "creditCard": {
            "creditCardFilterStrategies": [{"strategy": "LAST_4"}]
        }
    }
})

text = (
    "Name: Jane Smith, SSN: 987-65-4321, "
    "Phone: (555) 123-4567, Email: jane@example.com, "
    "Card: 5500 0000 0000 0004."
)

result = service.filter(policy, "app", "doc-7", text)
print(result.filtered_text)
# Name: Jane Smith, SSN: {{{REDACTED-ssn}}}, Phone: (***) ***-****, 
# Email: {{{REDACTED-email-address}}}, Card: ************0004.
```

---

## Inspect spans

Each `Span` in `result.spans` describes a single match:

```python
for span in result.spans:
    print(
        f"[{span.filter_type:20s}] "
        f"chars {span.character_start:3d}–{span.character_end:3d}  "
        f"'{span.text}'  →  '{span.replacement}'  "
        f"(confidence={span.confidence:.2f})"
    )
```

---

## Skip specific values with an ignore list

Prevent specific values from being redacted even when they match a filter pattern.

```python
policy = Policy.from_dict({
    "name": "ignored-emails",
    "identifiers": {
        "emailAddress": {
            "emailAddressFilterStrategies": [{"strategy": "REDACT"}],
            "ignored": ["noreply@internal.com", "admin@internal.com"]
        }
    }
})

result = service.filter(
    policy, "app", "doc-8",
    "Contact noreply@internal.com or john@example.com."
)
print(result.filtered_text)
# Contact noreply@internal.com or {{{REDACTED-email-address}}}.
```

---

## Skip values matching a regex pattern

Use `ignoredPatterns` at the top level to exclude matches by pattern.

```python
policy = Policy.from_dict({
    "name": "pattern-ignore",
    "identifiers": {
        "phoneNumber": {
            "phoneNumberFilterStrategies": [{"strategy": "REDACT"}]
        }
    },
    "ignoredPatterns": ["\\d{3}-555-\\d{4}"]  # keep 555 numbers unchanged
})

result = service.filter(
    policy, "app", "doc-9",
    "Call 555-555-1234 (public) or 800-867-5309 (private)."
)
print(result.filtered_text)
# Call 555-555-1234 (public) or {{{REDACTED-phone-number}}} (private).
```

---

## Load a policy from a JSON file

```python
import json
from phileas.policy.policy import Policy
from phileas.services.filter_service import FilterService

with open("policy.json") as f:
    policy = Policy.from_json(f.read())

service = FilterService()
result = service.filter(policy, "app", "doc-10", "Text to filter...")
```

---

## Load a policy from a YAML file

```python
from phileas.policy.policy import Policy
from phileas.services.filter_service import FilterService

with open("policy.yaml") as f:
    policy = Policy.from_yaml(f.read())

service = FilterService()
result = service.filter(policy, "app", "doc-11", "Text to filter...")
```

An example `policy.yaml`:

```yaml
name: my-policy
identifiers:
  emailAddress:
    emailAddressFilterStrategies:
      - strategy: REDACT
        redactionFormat: "{{{REDACTED-%t}}}"
  ssn:
    ssnFilterStrategies:
      - strategy: MASK
ignored:
  - admin@example.com
ignoredPatterns:
  - "\\d{3}-555-\\d{4}"
```

---

## NER-based person detection with ph-eye

Requires a running [ph-eye](https://github.com/philterd/ph-eye) service.

```python
policy = Policy.from_dict({
    "name": "ner-demo",
    "identifiers": {
        "phEye": [
            {
                "endpoint": "http://localhost:8080",
                "labels": ["PERSON"],
                "thresholds": {"PERSON": 0.85},
                "phEyeFilterStrategies": [{"strategy": "REDACT"}]
            }
        ]
    }
})

result = service.filter(
    policy, "app", "doc-12",
    "Dr. Alice Johnson reviewed the case."
)
print(result.filtered_text)
# Dr. {{{REDACTED-person}}} reviewed the case.
```
