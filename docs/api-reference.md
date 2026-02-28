# API Reference

## FilterService

`phileas.services.filter_service.FilterService`

The main entry point for filtering text. `FilterService` is stateless; a single instance can be reused across multiple calls.

```python
from phileas.services.filter_service import FilterService

service = FilterService()
```

### `filter(policy, context, document_id, text)`

Apply the policy to the given text and return a `FilterResult`.

```python
result = service.filter(
    policy=policy,
    context="my-app",
    document_id="doc-001",
    text="Contact john@example.com.",
)
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
