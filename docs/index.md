# phileas-python

**phileas-python** is a Python library for deidentifying and redacting PII (Personally Identifiable Information), PHI (Protected Health Information), and other sensitive data from text.

It is a Python port of [Phileas](https://github.com/philterd/phileas), an Apache-licensed open source project by [Philterd](https://www.philterd.ai).

## What phileas-python does

phileas-python scans text for sensitive information — email addresses, phone numbers, Social Security Numbers, credit card numbers, dates, and [many more types](#supported-pii-phi-types) — and replaces each match with a configurable replacement value. You control what to detect and how to replace it through **policies**.

```python
from phileas.policy.policy import Policy
from phileas.services.filter_service import FilterService

policy = Policy.from_dict({
    "name": "my-policy",
    "identifiers": {
        "emailAddress": {
            "emailAddressFilterStrategies": [{"strategy": "REDACT"}]
        },
        "phoneNumber": {
            "phoneNumberFilterStrategies": [{"strategy": "MASK"}]
        }
    }
})

service = FilterService()
result = service.filter(policy, "app", "doc-1", "Call me at 555-867-5309 or email me at john@example.com.")

print(result.filtered_text)
# Call me at ***-***-**** or email me at {{{REDACTED-email-address}}}.
```

## Supported PII / PHI Types

| Policy Key | Filter Type | Description |
|---|---|---|
| `age` | `age` | Age references (e.g., "35 years old") |
| `emailAddress` | `email-address` | Email addresses |
| `creditCard` | `credit-card` | Credit card numbers |
| `ssn` | `ssn` | Social Security Numbers and TINs |
| `phoneNumber` | `phone-number` | US phone numbers |
| `ipAddress` | `ip-address` | IPv4 and IPv6 addresses |
| `url` | `url` | HTTP/HTTPS URLs |
| `zipCode` | `zip-code` | US ZIP codes |
| `vin` | `vin` | Vehicle Identification Numbers |
| `bitcoinAddress` | `bitcoin-address` | Bitcoin addresses |
| `bankRoutingNumber` | `bank-routing-number` | US ABA bank routing numbers |
| `date` | `date` | Dates in common formats |
| `macAddress` | `mac-address` | Network MAC addresses |
| `currency` | `currency` | USD currency amounts |
| `streetAddress` | `street-address` | US street addresses |
| `trackingNumber` | `tracking-number` | UPS, FedEx, and USPS tracking numbers |
| `driversLicense` | `drivers-license` | US driver's license numbers |
| `ibanCode` | `iban-code` | International Bank Account Numbers |
| `passportNumber` | `passport-number` | US passport numbers |
| `phEye` | `person` (and others) | Named entities via the [ph-eye](https://github.com/philterd/ph-eye) NER service |

## Next steps

- [Install phileas-python](installation.md)
- [Run your first filter](quickstart.md)
- [Understand policies](policies.md)
- [Browse code examples](examples.md)
- [Read the API reference](api-reference.md)
