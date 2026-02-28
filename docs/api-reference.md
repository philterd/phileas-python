# API Reference

## FilterService

`phileas.services.filter_service.FilterService`

The main entry point for filtering text. `FilterService` is stateless; a single instance can be reused across multiple calls.

```python
from phileas.services.filter_service import FilterService
from phileas.policy.policy import Policy

# Create with default in-memory context service
service = FilterService()

# Or provide a custom context service
from phileas.services.context_service import InMemoryContextService
ctx_svc = InMemoryContextService()
service = FilterService(context_service=ctx_svc)
```

### Constructor

```python
FilterService(context_service=None)
```

**Parameters**

| Parameter | Type | Default | Description |
|---|---|---|
| `context_service` | `AbstractContextService` or `None` | `None` | Context service implementation for managing referential integrity. If `None`, an `InMemoryContextService` is created automatically. |

### `filter(policy, context, document_id, text)`

Apply the policy to the given text and return a `FilterResult`.

```python
from phileas.services.filter_service import FilterService
from phileas.policy.policy import Policy

policy = Policy.from_dict({
    "name": "example",
    "identifiers": {
        "emailAddress": {
            "emailAddressFilterStrategies": [{"strategy": "REDACT"}]
        }
    }
})

service = FilterService()
result = service.filter(
    policy=policy,
    context="my-app",
    document_id="doc-001",
    text="Contact john@example.com.",
)

print(result.filtered_text)
# Contact {{{REDACTED-email-address}}}.
```

**Parameters**

| Parameter | Type | Description |
|---|---|---|
| `policy` | `Policy` | The policy to apply |
| `context` | `str` | An arbitrary string identifying the caller or application (e.g. user name, service name). Stored in each returned `Span`. |
| `document_id` | `str` | A unique identifier for the document being filtered. Stored in the returned `FilterResult`. |
| `text` | `str` | The text to filter |

**Returns** — `FilterResult`

---

## Policy

`phileas.policy.policy.Policy`

Represents a de-identification policy.

```python
from phileas.policy.policy import Policy
```

### Constructors

#### `Policy.from_dict(data)`

Create a `Policy` from a Python dictionary.

```python
policy = Policy.from_dict({
    "name": "my-policy",
    "identifiers": {
        "emailAddress": {
            "emailAddressFilterStrategies": [{"strategy": "REDACT"}]
        }
    }
})
```

#### `Policy.from_json(json_str)`

Create a `Policy` from a JSON string.

```python
policy = Policy.from_json('{"name": "p", "identifiers": {...}}')
```

#### `Policy.from_yaml(yaml_str)`

Create a `Policy` from a YAML string.

```python
policy = Policy.from_yaml("name: p\nidentifiers:\n  ...")
```

### Methods

#### `to_dict()`

Serialise the policy to a Python dict.

#### `to_json()`

Serialise the policy to a JSON string (pretty-printed).

#### `to_yaml()`

Serialise the policy to a YAML string.

### Attributes

| Attribute | Type | Description |
|---|---|---|
| `name` | `str` | Policy name |
| `identifiers` | `Identifiers` | Filter configuration |
| `ignored` | `list[str]` | Global ignore list |
| `ignored_patterns` | `list[str]` | Global ignore patterns (regex) |

---

## FilterResult

`phileas.models.filter_result.FilterResult`

Returned by `FilterService.filter()`. Contains the filtered text and metadata for every match.

```python
from phileas.models.filter_result import FilterResult
```

### Attributes

| Attribute | Type | Description |
|---|---|---|
| `filtered_text` | `str` | The input text with sensitive values replaced |
| `spans` | `list[Span]` | One `Span` per detected piece of sensitive information |
| `context` | `str` | The `context` value passed to `filter()` |
| `document_id` | `str` | The `document_id` value passed to `filter()` |

---

## Span

`phileas.models.span.Span`

Describes a single detected piece of sensitive information.

```python
from phileas.models.span import Span
```

### Attributes

| Attribute | Type | Description |
|---|---|---|
| `character_start` | `int` | Start index (inclusive) of the match in the original text |
| `character_end` | `int` | End index (exclusive) of the match in the original text |
| `filter_type` | `str` | The type of PII detected (e.g. `"email-address"`, `"ssn"`) |
| `text` | `str` | The original matched text |
| `replacement` | `str` | The replacement value applied to the text |
| `confidence` | `float` | Confidence score in the range 0.0–1.0 |
| `ignored` | `bool` | `True` if the span was matched but not replaced (because it appeared in an ignore list or matched an ignored pattern) |
| `context` | `str` | The `context` value from the `filter()` call |

### Methods

#### `overlaps(other)`

Return `True` if this span overlaps with `other`.

#### `Span.drop_overlapping_spans(spans)` *(static)*

Given a list of spans, remove overlapping ones, keeping the span with the highest confidence score. Returns a new list sorted by `character_start`.

---

## FilterStrategy

`phileas.policy.filter_strategy.FilterStrategy`

Holds the replacement configuration for a single filter strategy entry.

### Constants

| Constant | Value |
|---|---|
| `REDACT` | `"REDACT"` |
| `MASK` | `"MASK"` |
| `STATIC_REPLACE` | `"STATIC_REPLACE"` |
| `HASH_SHA256_REPLACE` | `"HASH_SHA256_REPLACE"` |
| `LAST_4` | `"LAST_4"` |
| `SAME` | `"SAME"` |
| `TRUNCATE` | `"TRUNCATE"` |
| `ABBREVIATE` | `"ABBREVIATE"` |
| `RANDOM_REPLACE` | `"RANDOM_REPLACE"` |
| `SHIFT_DATE` | `"SHIFT_DATE"` |

### Constructor

```python
FilterStrategy(
    strategy="REDACT",
    redaction_format="{{{REDACTED-%t}}}",
    static_replacement="",
    mask_character="*",
    mask_length="SAME",
    condition="",
    shift_years=0,
    shift_months=0,
    shift_days=0,
)
```

### Methods

#### `get_replacement(filter_type, token)`

Return the replacement string for `token` based on the configured strategy.

#### `FilterStrategy.from_dict(data)` *(class method)*

Create a `FilterStrategy` from a dict such as `{"strategy": "REDACT", "redactionFormat": "..."}`.

#### `to_dict()`

Serialise to a dict.

---

## AbstractContextService

`phileas.services.context_service.AbstractContextService`

Abstract base class for context service implementations. Subclass this to provide a custom backend (e.g., Redis, database, etc.).

```python
from phileas.services.context_service import AbstractContextService
from phileas.services.filter_service import FilterService
from phileas.policy.policy import Policy

class RedisContextService(AbstractContextService):
    """Example custom context service using Redis."""

    def __init__(self, redis_client):
        self.redis = redis_client

    def put(self, context: str, token: str, replacement: str) -> None:
        """Store token -> replacement mapping in Redis."""
        key = f"phileas:{context}:{token}"
        self.redis.set(key, replacement)

    def get(self, context: str, token: str) -> str | None:
        """Retrieve replacement from Redis, or None if not found."""
        key = f"phileas:{context}:{token}"
        value = self.redis.get(key)
        return value.decode('utf-8') if value else None

    def contains(self, context: str, token: str) -> bool:
        """Check if token exists in Redis."""
        key = f"phileas:{context}:{token}"
        return self.redis.exists(key) > 0

# Usage example (requires redis package)
# import redis
# redis_client = redis.Redis(host='localhost', port=6379, db=0)
# ctx_svc = RedisContextService(redis_client)
# service = FilterService(context_service=ctx_svc)
```

### Methods

| Method | Signature | Description |
|---|---|---|
| `put` | `(context, token, replacement) -> None` | Store a replacement value for a token under the given context |
| `get` | `(context, token) -> str \| None` | Return the stored replacement, or `None` if not found |
| `contains` | `(context, token) -> bool` | Return `True` if a replacement exists for the token in the given context |

---

## InMemoryContextService

`phileas.services.context_service.InMemoryContextService`

Default implementation of `AbstractContextService` backed by a `dict[str, dict[str, str]]`. Suitable for single-process, in-memory use.

```python
from phileas.services.context_service import InMemoryContextService
from phileas.services.filter_service import FilterService
from phileas.policy.policy import Policy

# Create and pre-populate the context service
ctx_svc = InMemoryContextService()
ctx_svc.put("patient-123", "john@example.com", "EMAIL-001")
ctx_svc.put("patient-123", "555-867-5309", "PHONE-001")

# Use it with FilterService
policy = Policy.from_dict({
    "name": "medical",
    "identifiers": {
        "emailAddress": {
            "emailAddressFilterStrategies": [{"strategy": "REDACT"}]
        },
        "phoneNumber": {
            "phoneNumberFilterStrategies": [{"strategy": "REDACT"}]
        }
    }
})

service = FilterService(context_service=ctx_svc)

# The pre-populated replacements will be used
result1 = service.filter(
    policy, "patient-123", "doc-1",
    "Contact john@example.com or 555-867-5309."
)
print(result1.filtered_text)
# Contact EMAIL-001 or PHONE-001.

# The same replacements persist across documents in the same context
result2 = service.filter(
    policy, "patient-123", "doc-2",
    "Patient called 555-867-5309 from john@example.com."
)
print(result2.filtered_text)
# Patient called PHONE-001 from EMAIL-001.

# Check what's stored
print(ctx_svc.get("patient-123", "john@example.com"))      # EMAIL-001
print(ctx_svc.contains("patient-123", "555-867-5309"))     # True
print(ctx_svc.get("patient-123", "unknown@example.com"))   # None
```

### Methods

| Method | Signature | Description |
|---|---|---|
| `put` | `(context, token, replacement) -> None` | Store a replacement for a token |
| `get` | `(context, token) -> str \| None` | Retrieve a replacement, or `None` if not found |
| `contains` | `(context, token) -> bool` | Check if a replacement exists |

---

## Policy key reference

The table below maps every JSON/YAML policy key to the `Identifiers` attribute it populates and the strategies key used in its filter config.

| Policy key | `Identifiers` attribute | Strategies key |
|---|---|---|
| `age` | `age` | `ageFilterStrategies` |
| `emailAddress` | `email_address` | `emailAddressFilterStrategies` |
| `creditCard` | `credit_card` | `creditCardFilterStrategies` |
| `ssn` | `ssn` | `ssnFilterStrategies` |
| `phoneNumber` | `phone_number` | `phoneNumberFilterStrategies` |
| `ipAddress` | `ip_address` | `ipAddressFilterStrategies` |
| `url` | `url` | `urlFilterStrategies` |
| `zipCode` | `zip_code` | `zipCodeFilterStrategies` |
| `vin` | `vin` | `vinFilterStrategies` |
| `bitcoinAddress` | `bitcoin_address` | `bitcoinAddressFilterStrategies` |
| `bankRoutingNumber` | `bank_routing_number` | `bankRoutingNumberFilterStrategies` |
| `date` | `date` | `dateFilterStrategies` |
| `macAddress` | `mac_address` | `macAddressFilterStrategies` |
| `currency` | `currency` | `currencyFilterStrategies` |
| `streetAddress` | `street_address` | `streetAddressFilterStrategies` |
| `trackingNumber` | `tracking_number` | `trackingNumberFilterStrategies` |
| `driversLicense` | `drivers_license` | `driversLicenseFilterStrategies` |
| `ibanCode` | `iban_code` | `ibanCodeFilterStrategies` |
| `passportNumber` | `passport_number` | `passportNumberFilterStrategies` |
| `phEye` | `ph_eye` (list) | `phEyeFilterStrategies` |
