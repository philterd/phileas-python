# Quick Start

This page walks you through the core workflow: define a policy, create a `FilterService`, and filter text.

## Step 1 – Define a policy

A policy is a Python `dict` (or JSON/YAML string) that declares which PII types to detect and how to handle them. The simplest policy enables one filter with the default `REDACT` strategy:

```python
policy_dict = {
    "name": "my-policy",
    "identifiers": {
        "emailAddress": {
            "emailAddressFilterStrategies": [{"strategy": "REDACT"}]
        }
    }
}
```

See [Policies](policies.md) for the full structure and all available strategies.

## Step 2 – Create a Policy object

```python
from phileas.policy.policy import Policy

policy = Policy.from_dict(policy_dict)
```

Policies can also be loaded from a JSON string or a YAML string:

```python
import json

policy = Policy.from_json(json.dumps(policy_dict))
```

```python
policy = Policy.from_yaml("""
name: my-policy
identifiers:
  emailAddress:
    emailAddressFilterStrategies:
      - strategy: REDACT
""")
```

## Step 3 – Create a FilterService and filter text

```python
from phileas.services.filter_service import FilterService

service = FilterService()

result = service.filter(
    policy=policy,
    context="my-app",
    document_id="doc-001",
    text="Please contact support@example.com for help.",
)
```

`FilterService` is stateless and reusable — create a single instance and call `filter()` as many times as needed.

## Step 4 – Inspect the result

The returned `FilterResult` contains the redacted text and a list of `Span` objects describing every match:

```python
print(result.filtered_text)
# Please contact {{{REDACTED-email-address}}} for help.

for span in result.spans:
    print(
        f"[{span.filter_type}] "
        f"'{span.text}' → '{span.replacement}' "
        f"chars {span.character_start}–{span.character_end}"
    )
# [email-address] 'support@example.com' → '{{{REDACTED-email-address}}}' chars 16–35
```

## Putting it all together

```python
from phileas.policy.policy import Policy
from phileas.services.filter_service import FilterService

policy = Policy.from_dict({
    "name": "demo",
    "identifiers": {
        "emailAddress": {
            "emailAddressFilterStrategies": [{"strategy": "REDACT"}]
        },
        "ssn": {
            "ssnFilterStrategies": [{"strategy": "REDACT"}]
        },
        "phoneNumber": {
            "phoneNumberFilterStrategies": [{"strategy": "MASK"}]
        }
    }
})

service = FilterService()
text = "SSN 123-45-6789, phone 555-867-5309, email bob@example.com."

result = service.filter(policy, "demo-app", "doc-1", text)
print(result.filtered_text)
# SSN {{{REDACTED-ssn}}}, phone ***-***-****, email {{{REDACTED-email-address}}}.
```

## Next steps

- [Learn about all policy options](policies.md)
- [See all supported filter types](filters.md)
- [Browse more code examples](examples.md)
