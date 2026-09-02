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

!!! note "Catalog-derived field names"
    Because policy field names come from the PhiSQL catalog, a few are non-obvious. ZIP codes use the **singular** `zipCodeFilterStrategy`, and Bitcoin addresses use `bitcoinFilterStrategies`. Policies emitted by the PhiSQL compiler already use the correct names.

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

The set of valid strategies comes from the PhiSQL catalog. The `strategy` value in a policy is the catalog's `phileas_enum`; the matching PhiSQL keyword is shown for reference.

| Strategy | PhiSQL keyword | Description | Example output |
|---|---|---|---|
| `REDACT` | `REDACT` | Replace with a redaction tag | `{{{REDACTED-email-address}}}` |
| `MASK` | `MASK` | Replace every character with `maskCharacter` (default `*`) | `***@*******.***` |
| `RANDOM_REPLACE` | `RANDOM_REPLACE` | Replace with a randomly generated value of the same type | `jane@domain.org` |
| `STATIC_REPLACE` | `STATIC_REPLACE` | Replace with a fixed string | `[REMOVED]` |
| `CRYPTO_REPLACE` | `ENCRYPT` | Encrypt the value (requires an externally-configured key); emits a stable marker in this engine | `{{{ENCRYPTED-ssn}}}` |
| `FPE_ENCRYPT_REPLACE` | `FPE_ENCRYPT` | Format-preserving encryption (requires an externally-configured key); emits a stable marker in this engine | `{{{ENCRYPTED-ssn}}}` |
| `HASH_SHA256_REPLACE` | `HASH_SHA256` | Replace with the SHA-256 hex digest of the matched value | `a665a4592...` |
| `LAST_4` | `LAST_4` | Mask all but the last 4 characters | `****6789` |
| `TRUNCATE` | `TRUNCATE` | Keep only the first 4 characters | `john***` |
| `TRUNCATE_TO_YEAR` | `TRUNCATE_TO_YEAR` | Reduce a detected date to just its year | `1990` |
| `SHIFT` | `SHIFT` | Shift a detected date by a configurable number of years/months/days | `01/20/1995` |
| `RELATIVE` | `RELATIVE` | Pass the value through unchanged | `123-45-6789` |
| `ABBREVIATE` | `ABBREVIATE` | Replace with the initials of each word | `J. S.` |

`CRYPTO_REPLACE` and `FPE_ENCRYPT_REPLACE` require an externally-configured key and emit a stable marker in this engine. `RELATIVE` passes the value through unchanged.

### Strategy options

```yaml
strategy: REDACT
redactionFormat: "{{{REDACTED-%t}}}"
staticReplacement: "[REMOVED]"
maskCharacter: "*"
condition: ""
shiftYears: 0
shiftMonths: 0
shiftDays: 0
color: black
```

- **`redactionFormat`** — used by `REDACT`. The placeholder `%t` is replaced with the filter type name (e.g. `email-address`).
- **`staticReplacement`** — used by `STATIC_REPLACE`.
- **`maskCharacter`** — character used by `MASK` (default: `*`).
- **`shiftYears` / `shiftMonths` / `shiftDays`** — offsets used by `SHIFT`.
- **`condition`** — optional expression that must evaluate to `true` for this strategy to be applied. See [Conditions](#conditions) below.
- **`color`** — colour of the bar drawn over a redacted span when a policy is used to render a PDF or image. Accepted and ignored here: phileas-python redacts text, so `color` never changes its output. It is kept so one policy can be shared with the PDF-capable Java engine.

### Examples

```python
# Redact with a custom format
{"strategy": "REDACT", "redactionFormat": "[PII-%t]"}

# Mask with a custom character
{"strategy": "MASK", "maskCharacter": "X"}

# Replace with a fixed string
{"strategy": "STATIC_REPLACE", "staticReplacement": "[REMOVED]"}

# Shift a date forward by 2 years and 3 days
{"strategy": "SHIFT", "shiftYears": 2, "shiftDays": 3}
```

## Conditions

A `condition` expression is an optional string attached to a strategy that gates its application. The strategy is only applied when the condition evaluates to `true`. When multiple strategies are listed, the first one whose condition is satisfied is used.

> The key is `condition` (singular), matching the redaction policy schema and the Java and .NET Phileas runtimes. The plural `conditions` is accepted as a deprecated alias for backward compatibility and may be removed in a future release; prefer `condition`.

Sub-expressions may be combined with `and` and `or`, and grouped with parentheses. Conditions can test `confidence`, `token`, `context`, and `population`:

```python
{"strategy": "REDACT", "condition": 'token startswith "4" and confidence >= 0.9'}
```

```python
{"strategy": "REDACT", "condition": '(token startswith "4" or token startswith "5") and confidence >= 0.9'}
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
        "zipCodeFilterStrategy": [
            {"strategy": "REDACT", "condition": "population < 20000"}
        ]
    }
}
```

```python
# Redact small ZIP codes; statically replace large ones
s_small = {"strategy": "REDACT",         "condition": "population < 20000"}
s_large = {"strategy": "STATIC_REPLACE", "staticReplacement": "[LARGE-ZIP]",
           "condition": "population >= 20000"}

{
    "zipCode": {
        "zipCodeFilterStrategy": [s_small, s_large]
    }
}
```

The condition can also be combined with other expressions using `and` or `or`:

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

[ph-eye](https://github.com/philterd/ph-eye) is a standalone NER service that phileas-python can call to detect named entities such as person names. Alternatively, phileas-python can perform local on-device inference using [GLiNER](https://github.com/urchade/GLiNER) when `modelPath` points at a local model directory. When `modelPath` is set, detection runs on-device and no remote endpoint is called.

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

To use local on-device inference, set `modelPath` to a local GLiNER model **directory**: a folder containing the exported ONNX model (`model.onnx`), its tokenizer, and the GLiNER config (the layout produced for the `pheye-local-model` example). When `modelPath` is set, detection runs on-device and no remote endpoint is called, even if one is configured. `labels` is the GLiNER detection prompt, and `threshold` (default `0.5`) is the minimum span confidence. This is what the PhiSQL `DETECT PHEYE ... MODEL '<path>'` clause compiles to.

```python
policy = Policy.from_dict({
    "name": "local-ner-policy",
    "identifiers": {
        "phEye": [
            {
                "modelPath": "/path/to/ph-eye-model",
                "labels": ["PERSON"],
                "threshold": 0.5,
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
| `modelPath` | string | `""` | Path to a local GLiNER model directory (ONNX model, tokenizer, and GLiNER config). When set, detection runs on-device and takes precedence over `endpoint`. |
| `threshold` | number | `0.5` | Minimum span confidence for the local model to return a detection |
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
