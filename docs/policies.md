# Policies

A **policy** is the configuration object that tells phileas-python what to detect and what to do with each match. Policies are expressed as Python dicts, JSON strings, or YAML strings and are loaded into a `Policy` object before being passed to `FilterService`.

## Policy structure

```json
{
  "name": "my-policy",
  "identifiers": {
    "<filterKey>": {
      "enabled": true,
      "<filterKey>FilterStrategies": [
        {
          "strategy": "REDACT",
          "redactionFormat": "{{{REDACTED-%t}}}"
        }
      ],
      "ignored": ["value-to-skip"]
    }
  },
  "ignored": ["global-term-to-skip"],
  "ignoredPatterns": ["\\d{3}-555-\\d{4}"]
}
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

```json
{
  "strategy": "REDACT",
  "redactionFormat": "{{{REDACTED-%t}}}",
  "staticReplacement": "[REMOVED]",
  "maskCharacter": "*",
  "maskLength": "SAME",
  "shiftYears": 0,
  "shiftMonths": 0,
  "shiftDays": 0
}
```

- **`redactionFormat`** — used by `REDACT`. The placeholder `%t` is replaced with the filter type name (e.g. `email-address`).
- **`staticReplacement`** — used by `STATIC_REPLACE`.
- **`maskCharacter`** — character used by `MASK` (default: `*`).
- **`shiftYears` / `shiftMonths` / `shiftDays`** — offsets used by `SHIFT_DATE`.

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

[ph-eye](https://github.com/philterd/ph-eye) is a standalone NER service that phileas-python can call to detect named entities such as person names. Add a `phEye` block to use it:

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

| Option | Type | Default | Description |
|---|---|---|---|
| `endpoint` | string | `""` | Base URL of the ph-eye service |
| `bearerToken` | string | `""` | Optional Bearer token for authentication |
| `timeout` | int | `30` | Request timeout in seconds |
| `labels` | list of strings | `["PERSON"]` | NER label types to process |
| `thresholds` | object | `{}` | Minimum confidence per label, e.g. `{"PERSON": 0.9}` |
| `removePunctuation` | bool | `false` | Strip punctuation from entity text before replacement |
