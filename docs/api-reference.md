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
| `identifiers` | `dict` | Raw Phileas-JSON `identifiers` object — a plain `dict` mapping each entity field name to its filter node |
| `ignored` | `list[str]` | Global ignore list — a flat list of strings, parsed from the PhiSQL `ignored` shape (a list of `{"terms": [...]}` objects) |
| `ignored_patterns` | `list[str]` | Global ignore patterns — a flat list of regex strings, parsed from the PhiSQL `ignoredPatterns` shape (a list of `{"pattern": "..."}` objects) |

`Policy.identifiers` is a plain `dict` holding the raw Phileas-JSON `identifiers` object (entity field name → filter node); there is no `Identifiers` class.

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

## Strategy

`phileas.policy.strategy.Strategy`

Wraps a single strategy JSON object (one entry from a filter's `*FilterStrategies` array), for example:

```python
{"strategy": "MASK", "maskCharacter": "X", "conditions": "confidence > 0.9"}
```

### Valid strategies

The valid `strategy` values come from the PhiSQL catalog (the `strategy` value is the catalog's `phileas_enum`):

`REDACT`, `MASK`, `RANDOM_REPLACE`, `STATIC_REPLACE`, `CRYPTO_REPLACE`, `FPE_ENCRYPT_REPLACE`, `HASH_SHA256_REPLACE`, `LAST_4`, `TRUNCATE`, `TRUNCATE_TO_YEAR`, `SHIFT`, `RELATIVE`, `ABBREVIATE`.

`CRYPTO_REPLACE` and `FPE_ENCRYPT_REPLACE` require an externally-configured key and emit a stable marker in this engine; `RELATIVE` passes the value through unchanged.

### Constructor

```python
Strategy(config: dict)
```

Build a `Strategy` from a single strategy JSON object.

### Class methods

#### `Strategy.from_dict(d)`

Create a `Strategy` from a dict such as `{"strategy": "REDACT", "redactionFormat": "..."}`.

#### `Strategy.default()`

Return a default `Strategy` (the `REDACT` strategy).

### Attributes

| Attribute | Type | Description |
|---|---|---|
| `strategy` | `str` | The strategy enum string (e.g. `"REDACT"`, `"MASK"`) |
| `conditions` | `str` | The optional condition expression that gates this strategy |

### Methods

#### `evaluate_condition(token, context, confidence) -> bool`

Return `True` if this strategy's `conditions` expression is satisfied for the given `token`, `context`, and `confidence` (a strategy with no condition always returns `True`).

#### `get_replacement(filter_type, token) -> str`

Return the replacement string for `token` based on the configured strategy.

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

`Policy.identifiers` is a plain `dict` keyed by the policy key (entity field name). The table below maps every JSON/YAML policy key to the strategies key used in its filter config. Because these field names come from the PhiSQL catalog, a few are non-obvious — note that `zipCode` uses the **singular** `zipCodeFilterStrategy` and `bitcoinAddress` uses `bitcoinFilterStrategies`.

| Policy key | Strategies key |
|---|---|
| `age` | `ageFilterStrategies` |
| `emailAddress` | `emailAddressFilterStrategies` |
| `creditCard` | `creditCardFilterStrategies` |
| `ssn` | `ssnFilterStrategies` |
| `phoneNumber` | `phoneNumberFilterStrategies` |
| `ipAddress` | `ipAddressFilterStrategies` |
| `url` | `urlFilterStrategies` |
| `zipCode` | `zipCodeFilterStrategy` |
| `vin` | `vinFilterStrategies` |
| `bitcoinAddress` | `bitcoinFilterStrategies` |
| `bankRoutingNumber` | `bankRoutingNumberFilterStrategies` |
| `date` | `dateFilterStrategies` |
| `macAddress` | `macAddressFilterStrategies` |
| `currency` | `currencyFilterStrategies` |
| `streetAddress` | `streetAddressFilterStrategies` |
| `trackingNumber` | `trackingNumberFilterStrategies` |
| `driversLicense` | `driversLicenseFilterStrategies` |
| `ibanCode` | `ibanCodeFilterStrategies` |
| `passportNumber` | `passportNumberFilterStrategies` |
| `phEye` | `phEyeFilterStrategies` |
