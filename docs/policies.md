# Policies

A **policy** is the configuration object that tells phileas-python what to detect and what to do with each match. Policies are expressed as Python dicts, JSON strings, or YAML strings and are loaded into a `Policy` object before being passed to `FilterService`.

## Policy structure

```yaml
name: my-policy
identifiers:
  emailAddress:
    enabled: true
    emailAddressFilterStrategies:
      - strategy: REDACT
        redactionFormat: "{{{REDACTED-%t}}}"
    ignored:
      - value-to-skip
ignored:
  - global-term-to-skip
ignoredPatterns:
  - "\\d{3}-555-\\d{4}"
```

| Field | Type | Description |
|---|---|---|
| `name` | string | A human-readable name for the policy |
| `identifiers` | object | Map of filter keys to their configuration |
| `ignored` | array of strings | Terms that are never replaced, regardless of the filter that matched them |
| `ignoredPatterns` | array of regex strings | Regex patterns whose full matches are never replaced |

## Loading a policy

```python
from phileas.policy.policy import Policy

# From a Python dict
policy = Policy.from_dict({...})

# From a JSON string
policy = Policy.from_json('{"name": "p", "identifiers": {...}}')

# From a YAML string
policy = Policy.from_yaml("name: p\nidentifiers:\n  ...")

# Serialise back
json_str = policy.to_json()
yaml_str = policy.to_yaml()
d = policy.to_dict()
```

## Enabling and disabling filters

Every filter is **disabled by default**. To enable a filter, include its key in `identifiers`. To explicitly disable a filter that would otherwise be enabled, set `"enabled": false`:

```python
policy = Policy.from_dict({
    "name": "selective",
    "identifiers": {
        "emailAddress": {
            "emailAddressFilterStrategies": [{"strategy": "REDACT"}]
        },
        "url": {"enabled": False}   # explicitly disabled
    }
})
```

## Filter strategies

Each enabled filter requires at least one strategy entry in its `*FilterStrategies` array. The first strategy is applied to every match.

### Available strategies

| Strategy | Description | Example output |
|---|---|---|
| `REDACT` | Replace with a redaction tag | `{{{REDACTED-email-address}}}` |
| `MASK` | Replace every character with `maskCharacter` (default `*`) | `***@*******.***` |
| `STATIC_REPLACE` | Replace with a fixed string | `[REMOVED]` |
| `HASH_SHA256_REPLACE` | Replace with the SHA-256 hex digest of the matched value | `a665a4592...` |
| `LAST_4` | Mask all but the last 4 characters | `****6789` |
| `SAME` | Leave the value unchanged (identify-only mode) | `123-45-6789` |
| `TRUNCATE` | Keep only the first 4 characters | `john***` |
| `ABBREVIATE` | Replace with the initials of each word | `J. S.` |
| `RANDOM_REPLACE` | Replace with a randomly generated value of the same type | `jane@domain.org` |
| `SHIFT_DATE` | Shift a detected date by a configurable number of years/months/days | `01/20/1995` |

### Strategy options

```yaml
strategy: REDACT
redactionFormat: "{{{REDACTED-%t}}}"
staticReplacement: "[REMOVED]"
maskCharacter: "*"
maskLength: SAME
condition: ""
shiftYears: 0
shiftMonths: 0
shiftDays: 0
```

- **`redactionFormat`** — used by `REDACT`. The placeholder `%t` is replaced with the filter type name (e.g. `email-address`).
- **`staticReplacement`** — used by `STATIC_REPLACE`.
- **`maskCharacter`** — character used by `MASK` (default: `*`).
- **`shiftYears` / `shiftMonths` / `shiftDays`** — offsets used by `SHIFT_DATE`.
- **`condition`** — optional expression that must evaluate to `true` for this strategy to be applied. See [Conditions](#conditions) below.

### Examples

```python
# Redact with a custom format
{"strategy": "REDACT", "redactionFormat": "[PII-%t]"}

# Mask with a custom character
{"strategy": "MASK", "maskCharacter": "X"}

# Replace with a fixed string
{"strategy": "STATIC_REPLACE", "staticReplacement": "[REMOVED]"}

# Shift a date forward by 2 years and 3 days
{"strategy": "SHIFT_DATE", "shiftYears": 2, "shiftDays": 3}
```

## Conditions

A `condition` expression is an optional string attached to a strategy that gates its application. The strategy is only applied when the condition evaluates to `true`. When multiple strategies are listed, the first one whose condition is satisfied is used.

Multiple sub-expressions may be combined with `and`:

```python
{"strategy": "REDACT", "condition": 'token startswith "4" and confidence >= 0.9'}
```

### Supported condition expressions

| Expression | Description |
|---|---|
| `token == "value"` | Matched text equals `value` (case-sensitive) |
| `token != "value"` | Matched text does not equal `value` |
| `token startswith "prefix"` | Matched text starts with `prefix` |
| `token endswith "suffix"` | Matched text ends with `suffix` |
| `token contains "substring"` | Matched text contains `substring` |
| `context == "value"` | Current context equals `value` |
| `context != "value"` | Current context does not equal `value` |
| `confidence <op> 0.9` | Match confidence compared to a threshold (`>`, `<`, `>=`, `<=`, `==`, `!=`) |
| `population <op> 20000` | ZIP code population compared to a threshold — see [Population condition](#population-condition) |

### Population condition

The `population` condition is specific to the `zipCode` filter. It evaluates to `true` when the 2020 US Census population of the matched ZIP code satisfies the given comparison. ZIP codes not found in the dataset evaluate to `false`.

Supported operators: `<`, `>`, `<=`, `>=`, `==`, `!=`.

```python
# Only redact ZIP codes with a population below 20,000
{
    "zipCode": {
        "zipCodeFilterStrategies": [
            {"strategy": "REDACT", "condition": "population < 20000"}
        ]
    }
}
```

```python
# Redact small ZIP codes; leave large ones unchanged (identify-only)
s_small = {"strategy": "REDACT",  "condition": "population < 20000"}
s_large = {"strategy": "SAME",    "condition": "population >= 20000"}

{
    "zipCode": {
        "zipCodeFilterStrategies": [s_small, s_large]
    }
}
```

The condition can also be combined with other expressions using `and`:

```python
{"strategy": "REDACT", "condition": 'population < 20000 and context == "medical"'}
```

## Ignored terms

Use `ignored` on an individual filter to skip specific values:

```python
{
    "emailAddress": {
        "emailAddressFilterStrategies": [{"strategy": "REDACT"}],
        "ignored": ["noreply@internal.com", "admin@internal.com"]
    }
}
```

Use the top-level `ignored` list to skip terms regardless of which filter matched them, and `ignoredPatterns` for regex-based exclusions:

```python
policy = Policy.from_dict({
    "name": "allow-list",
    "identifiers": {
        "phoneNumber": {
            "phoneNumberFilterStrategies": [{"strategy": "REDACT"}]
        }
    },
    "ignored": ["555-000-0000"],
    "ignoredPatterns": ["\\d{3}-555-\\d{4}"]   # ignore 555-xxx numbers
})
```

## ph-eye integration

[ph-eye](https://github.com/philterd/ph-eye) is a standalone NER service that phileas-python can call to detect named entities such as person names. Alternatively, phileas-python can perform local inference using [GLiNER](https://github.com/urchade/GLiNER) if `modelPath` and `vocabPath` are provided.

### Remote Inference (HTTP)

To use a remote ph-eye service, provide the `endpoint` URL:

```python
policy = Policy.from_dict({
    "name": "ner-policy",
    "identifiers": {
        "phEye": [
            {
                "endpoint": "http://localhost:8080",
                "bearerToken": "secret",
                "labels": ["PERSON", "LOCATION"],
                "thresholds": {"PERSON": 0.8},
                "phEyeFilterStrategies": [{"strategy": "REDACT"}]
            }
        ]
    }
})
```

### Local Inference (GLiNER)

To use local inference, provide the `modelPath` and `vocabPath`. If the `modelPath` ends with `.onnx`, the ONNX Runtime will be used.

```python
policy = Policy.from_dict({
    "name": "local-ner-policy",
    "identifiers": {
        "phEye": [
            {
                "modelPath": "/path/to/gliner_model.bin",
                "vocabPath": "/path/to/vocab.txt",
                "labels": ["PERSON"],
                "phEyeFilterStrategies": [{"strategy": "REDACT"}]
            }
        ]
    }
})
```

| Option | Type | Default | Description |
|---|---|---|---|
| `endpoint` | string | `""` | Base URL of the ph-eye service (for remote inference) |
| `bearerToken` | string | `""` | Optional Bearer token for authentication (for remote inference) |
| `modelPath` | string | `""` | Path to the local GLiNER model (e.g. `gliner_model.bin` or `gliner_model.onnx`) |
| `vocabPath` | string | `""` | Path to the vocabulary file required by GLiNER |
| `timeout` | int | `30` | Request timeout in seconds (for remote inference) |
| `labels` | list of strings | `["PERSON"]` | NER label types to process |
| `thresholds` | object | `{}` | Minimum confidence per label, e.g. `{"PERSON": 0.9}` |
| `removePunctuation` | bool | `false` | Strip punctuation from entity text before replacement |

## Dictionary filter

The `dictionaries` filter matches terms from a user-supplied list anywhere in the text. It is useful for redacting known names, keywords, or any other fixed vocabulary.

```python
from phileas.policy.policy import Policy
from phileas.services.filter_service import FilterService

policy = Policy.from_dict({
    "name": "dictionary-policy",
    "identifiers": {
        "dictionaries": [
            {
                "terms": ["John", "Jane Smith", "classified"],
                "dictionaryFilterStrategies": [{"strategy": "REDACT"}]
            }
        ]
    }
})

service = FilterService()
result = service.filter(
    policy, "app", "doc-1",
    "John called Jane Smith about the classified project."
)
print(result.filtered_text)
# {{{REDACTED-dictionary}}} called {{{REDACTED-dictionary}}} about the {{{REDACTED-dictionary}}} project.
```

Like `phEye`, `dictionaries` is a list — you can include multiple independent dictionaries in a single policy:

```python
from phileas.policy.policy import Policy
from phileas.services.filter_service import FilterService

policy = Policy.from_dict({
    "name": "multi-dict-policy",
    "identifiers": {
        "dictionaries": [
            {
                "terms": ["Alice", "Bob"],
                "dictionaryFilterStrategies": [
                    {"strategy": "STATIC_REPLACE", "staticReplacement": "[PERSON]"}
                ]
            },
            {
                "terms": ["secret", "classified"],
                "dictionaryFilterStrategies": [{"strategy": "REDACT"}]
            }
        ]
    }
})

service = FilterService()
result = service.filter(
    policy, "app", "doc-2",
    "Alice told Bob about the secret project marked classified."
)
print(result.filtered_text)
# [PERSON] told [PERSON] about the {{{REDACTED-dictionary}}} project marked {{{REDACTED-dictionary}}}.
```

| Option | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Whether this dictionary is active |
| `terms` | array of strings | `[]` | The list of terms to detect (case-insensitive, whole-word) |
| `dictionaryFilterStrategies` | array | `[{"strategy": "REDACT"}]` | Replacement strategies |
| `ignored` | array of strings | `[]` | Terms to skip even if present in `terms` |
