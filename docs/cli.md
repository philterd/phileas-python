# CLI

phileas includes a command-line interface (CLI) that lets you redact sensitive information from text directly from your terminal — no Python code required.

## Installation

The CLI is installed automatically with the phileas package:

```bash
pip install phileas
```

After installation, the `phileas` command is available in your shell.

## Usage

```
phileas -p POLICY_FILE -c CONTEXT (-t TEXT | -f FILE) [options]
```

### Required arguments

| Argument | Short | Description |
|---|---|---|
| `--policy FILE` | `-p` | Path to a policy file (JSON or YAML). |
| `--context CONTEXT` | `-c` | Context name used for referential integrity across documents. |
| `--text TEXT` | `-t` | Text to redact, supplied directly as a string. Mutually exclusive with `--file`. |
| `--file FILE` | `-f` | Path to a file whose contents should be redacted. Mutually exclusive with `--text`. |

### Optional arguments

| Argument | Short | Description |
|---|---|---|
| `--document-id ID` | `-d` | Document identifier. Auto-generated if omitted. |
| `--output FILE` | `-o` | Write the redacted text to FILE instead of stdout. |
| `--spans` | | Print span metadata as JSON to stderr after filtering. |

## Policy files

The `--policy` argument accepts a path to a JSON or YAML policy file. The file must conform to the phileas [policy schema](policies.md).

### JSON policy file example

```json
{
  "name": "my-policy",
  "identifiers": {
    "emailAddress": {
      "emailAddressFilterStrategies": [
        {"strategy": "REDACT", "redactionFormat": "{{{REDACTED-%t}}}"}
      ]
    },
    "ssn": {
      "ssnFilterStrategies": [
        {"strategy": "REDACT", "redactionFormat": "{{{REDACTED-%t}}}"}
      ]
    }
  }
}
```

### YAML policy file example

```yaml
name: my-policy
identifiers:
  emailAddress:
    emailAddressFilterStrategies:
      - strategy: REDACT
        redactionFormat: "{{{REDACTED-%t}}}"
  ssn:
    ssnFilterStrategies:
      - strategy: REDACT
        redactionFormat: "{{{REDACTED-%t}}}"
```

## Examples

### Redact a text string

```bash
phileas -p policy.json -c my-context -t "Contact john@example.com or call 800-555-1234."
```

Output:

```
Contact {{{REDACTED-email-address}}} or call {{{REDACTED-phone-number}}}.
```

### Redact the contents of a file

```bash
phileas -p policy.json -c my-context -f report.txt
```

The redacted text is written to stdout.

### Write redacted output to a file

```bash
phileas -p policy.json -c my-context -f report.txt -o report_redacted.txt
```

### Use a YAML policy file

```bash
phileas -p policy.yaml -c my-context -t "Patient SSN is 123-45-6789."
```

### Supply a custom document ID

```bash
phileas -p policy.json -c my-context -d doc-001 -t "Email: admin@example.com"
```

### View span metadata

Use `--spans` to print details about each detected piece of sensitive information as JSON on stderr:

```bash
phileas -p policy.json -c my-context -t "Email john@example.com." --spans
```

Stdout:
```
Email {{{REDACTED-email-address}}}.
```

Stderr:
```json
[
  {
    "characterStart": 6,
    "characterEnd": 22,
    "filterType": "email-address",
    "text": "john@example.com",
    "replacement": "{{{REDACTED-email-address}}}",
    "confidence": 1.0,
    "ignored": false,
    "context": "my-context"
  }
]
```

### Pipe text from another command

Pass a file to phileas with the `--file` flag:

```bash
phileas -p policy.json -c pipeline -f report.txt
```
