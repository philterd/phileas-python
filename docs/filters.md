# Filters

Each filter detects a specific type of sensitive information. Filters are enabled by including their key in the `identifiers` section of a policy and are disabled by default.

The table below lists every supported filter, the policy key used to enable it, the internal filter type name returned in `Span.filter_type`, and example matching values.

| Policy key | Filter type | Example matches |
|---|---|---|
| `age` | `age` | `35 years old`, `aged 25`, `12-year-old` |
| `emailAddress` | `email-address` | `user@example.com` |
| `creditCard` | `credit-card` | `4111 1111 1111 1111`, `5500-0000-0000-0004` |
| `ssn` | `ssn` | `123-45-6789`, `123 45 6789` |
| `phoneNumber` | `phone-number` | `(555) 867-5309`, `555.867.5309` |
| `ipAddress` | `ip-address` | `192.168.1.1`, `2001:db8::1` |
| `url` | `url` | `https://www.example.com/path?q=1` |
| `zipCode` | `zip-code` | `90210`, `10001-1234` |
| `vin` | `vin` | `1HGBH41JXMN109186` |
| `bitcoinAddress` | `bitcoin-address` | `1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf…` |
| `bankRoutingNumber` | `bank-routing-number` | `021000021` |
| `date` | `date` | `01/15/1990`, `January 15, 1990`, `1990-01-15` |
| `macAddress` | `mac-address` | `00:1A:2B:3C:4D:5E`, `00-1A-2B-3C-4D-5E` |
| `currency` | `currency` | `$1,234.56`, `$99.99` |
| `streetAddress` | `street-address` | `123 Main St`, `456 Elm Avenue` |
| `trackingNumber` | `tracking-number` | UPS, FedEx, and USPS tracking numbers |
| `driversLicense` | `drivers-license` | US state driver's license numbers |
| `ibanCode` | `iban-code` | `GB82 WEST 1234 5698 7654 32` |
| `passportNumber` | `passport-number` | US passport numbers (e.g. `A12345678`) |
| `phEye` | `person`, `location`, etc. | Any NER entity returned by [ph-eye](https://github.com/philterd/ph-eye) |
| `dictionaries` | `dictionary` | Any term from a user-supplied list (e.g. `John`, `classified`) |

---

## age

Detects age references in text such as "35 years old", "aged 25", or "a 12-year-old child".

```python
"identifiers": {
    "age": {
        "ageFilterStrategies": [{"strategy": "REDACT"}]
    }
}
```

---

## emailAddress

Detects standard email addresses (`local@domain.tld`).

```python
"identifiers": {
    "emailAddress": {
        "emailAddressFilterStrategies": [{"strategy": "REDACT"}],
        "ignored": ["noreply@example.com"]
    }
}
```

---

## creditCard

Detects major credit card number formats (Visa, Mastercard, American Express, Discover, and others), with or without spaces/hyphens.

```python
"identifiers": {
    "creditCard": {
        "creditCardFilterStrategies": [{"strategy": "LAST_4"}]
    }
}
```

---

## ssn

Detects US Social Security Numbers (SSNs) and Taxpayer Identification Numbers (TINs) in `NNN-NN-NNNN` and `NNN NN NNNN` formats.

```python
"identifiers": {
    "ssn": {
        "ssnFilterStrategies": [{"strategy": "HASH_SHA256_REPLACE"}]
    }
}
```

---

## phoneNumber

Detects US phone numbers in common formats: `(555) 867-5309`, `555-867-5309`, `555.867.5309`.

```python
"identifiers": {
    "phoneNumber": {
        "phoneNumberFilterStrategies": [{"strategy": "MASK"}]
    }
}
```

---

## ipAddress

Detects IPv4 addresses (e.g. `192.168.1.1`) and IPv6 addresses (e.g. `2001:db8::1`).

```python
"identifiers": {
    "ipAddress": {
        "ipAddressFilterStrategies": [{"strategy": "STATIC_REPLACE", "staticReplacement": "0.0.0.0"}]
    }
}
```

---

## url

Detects HTTP and HTTPS URLs.

```python
"identifiers": {
    "url": {
        "urlFilterStrategies": [{"strategy": "REDACT"}]
    }
}
```

---

## zipCode

Detects 5-digit ZIP codes (`90210`) and ZIP+4 codes (`90210-1234`).

```python
"identifiers": {
    "zipCode": {
        "zipCodeFilterStrategies": [{"strategy": "REDACT"}]
    }
}
```

### Population condition

The `zipCode` filter supports a `population` condition that limits redaction to ZIP codes whose 2020 US Census population satisfies a numeric threshold. ZIP codes not present in the dataset are treated as non-matching.

```python
# Redact only ZIP codes with a population below 20,000
"identifiers": {
    "zipCode": {
        "zipCodeFilterStrategies": [
            {"strategy": "REDACT", "condition": "population < 20000"}
        ]
    }
}
```

Supported operators: `<`, `>`, `<=`, `>=`, `==`, `!=`. The condition also works with ZIP+4 codes — the 5-digit prefix is used for the lookup (`90210-1234` → `90210`).

See [Conditions](policies.md#conditions) for details on combining conditions with `and` and using other condition types.

---

## vin

Detects 17-character Vehicle Identification Numbers.

```python
"identifiers": {
    "vin": {
        "vinFilterStrategies": [{"strategy": "REDACT"}]
    }
}
```

---

## bitcoinAddress

Detects Bitcoin addresses (P2PKH addresses starting with `1`, P2SH addresses starting with `3`, and bech32 addresses starting with `bc1`).

```python
"identifiers": {
    "bitcoinAddress": {
        "bitcoinAddressFilterStrategies": [{"strategy": "REDACT"}]
    }
}
```

---

## bankRoutingNumber

Detects US ABA bank routing numbers (9-digit numbers).

```python
"identifiers": {
    "bankRoutingNumber": {
        "bankRoutingNumberFilterStrategies": [{"strategy": "MASK"}]
    }
}
```

---

## date

Detects dates in several common formats:

- `MM/DD/YYYY` and `MM-DD-YYYY`
- `YYYY-MM-DD` (ISO 8601)
- `Month DD, YYYY` (e.g. `January 15, 1990`)
- `DD Month YYYY` (e.g. `15 January 1990`)

```python
"identifiers": {
    "date": {
        "dateFilterStrategies": [{"strategy": "SHIFT_DATE", "shiftYears": 1}]
    }
}
```

---

## macAddress

Detects network MAC addresses in colon-separated (`AA:BB:CC:DD:EE:FF`) and hyphen-separated (`AA-BB-CC-DD-EE-FF`) formats.

```python
"identifiers": {
    "macAddress": {
        "macAddressFilterStrategies": [{"strategy": "REDACT"}]
    }
}
```

---

## currency

Detects US dollar amounts such as `$1,234.56` and `$99.99`.

```python
"identifiers": {
    "currency": {
        "currencyFilterStrategies": [{"strategy": "REDACT"}]
    }
}
```

---

## streetAddress

Detects US street address patterns such as `123 Main St` or `456 Elm Avenue`.

```python
"identifiers": {
    "streetAddress": {
        "streetAddressFilterStrategies": [{"strategy": "REDACT"}]
    }
}
```

---

## trackingNumber

Detects UPS, FedEx, and USPS package tracking numbers.

```python
"identifiers": {
    "trackingNumber": {
        "trackingNumberFilterStrategies": [{"strategy": "REDACT"}]
    }
}
```

---

## driversLicense

Detects US driver's license numbers (pattern varies by state).

```python
"identifiers": {
    "driversLicense": {
        "driversLicenseFilterStrategies": [{"strategy": "REDACT"}]
    }
}
```

---

## ibanCode

Detects International Bank Account Numbers (IBANs) for all supported country codes.

```python
"identifiers": {
    "ibanCode": {
        "ibanCodeFilterStrategies": [{"strategy": "MASK"}]
    }
}
```

---

## passportNumber

Detects US passport numbers in the format `A12345678` (one letter followed by eight digits).

```python
"identifiers": {
    "passportNumber": {
        "passportNumberFilterStrategies": [{"strategy": "REDACT"}]
    }
}
```

---

## phEye (NER via ph-eye)

The `phEye` filter delegates named entity recognition to the [ph-eye](https://github.com/philterd/ph-eye) service over HTTP. Unlike the regex-based filters above, ph-eye uses a machine-learning NER model and can detect entities such as person names, locations, and organisations.

Multiple `phEye` configurations can be listed in an array (for example, to call different ph-eye instances with different label sets).

```python
"identifiers": {
    "phEye": [
        {
            "endpoint": "http://localhost:8080",
            "bearerToken": "my-token",
            "labels": ["PERSON"],
            "thresholds": {"PERSON": 0.85},
            "phEyeFilterStrategies": [{"strategy": "REDACT"}]
        }
    ]
}
```

See [Policies – ph-eye integration](policies.md#ph-eye-integration) for all configuration options.

---

## dictionaries

The `dictionaries` filter lets you supply a list of terms that should be detected and replaced in text. Matching is case-insensitive and is constrained to whole-word boundaries so that a term like `John` does not match inside `Johnson`.

Internally the filter uses a **Bloom filter** for fast O(1) rejection of tokens that are definitely not in the dictionary, followed by an exact-set lookup to eliminate any Bloom false-positives. This makes the filter efficient even for large term lists.

Multiple independent dictionaries can be listed in an array. Each entry may have its own term list, strategy, and ignored terms.

```python
"identifiers": {
    "dictionaries": [
        {
            "enabled": true,
            "terms": ["John", "Jane Smith", "classified"],
            "dictionaryFilterStrategies": [{"strategy": "REDACT"}],
            "ignored": []
        }
    ]
}
```

| Option | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Whether this dictionary is active |
| `terms` | array of strings | `[]` | The list of terms to detect |
| `dictionaryFilterStrategies` | array | `[{"strategy": "REDACT"}]` | Replacement strategies (same as other filters) |
| `ignored` | array of strings | `[]` | Terms to skip even if found in the `terms` list |

### Multiple dictionaries

You can define several dictionaries in the same policy — for example, one for person names and another for sensitive keywords:

```python
"identifiers": {
    "dictionaries": [
        {
            "terms": ["Alice", "Bob", "Charlie"],
            "dictionaryFilterStrategies": [{"strategy": "STATIC_REPLACE", "staticReplacement": "[PERSON]"}]
        },
        {
            "terms": ["secret", "classified", "top-secret"],
            "dictionaryFilterStrategies": [{"strategy": "REDACT"}]
        }
    ]
}
```
