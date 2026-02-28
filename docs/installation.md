# Installation

## Requirements

- Python 3.9 or later
- [PyYAML](https://pypi.org/project/PyYAML/) (installed automatically as a dependency)

## Install from PyPI

```bash
pip install phileas-redact
```

## Install in development mode

Clone the repository and install with the `dev` extras to get testing and documentation dependencies:

```bash
git clone https://github.com/philterd/phileas-python.git
cd phileas-python
pip install -e ".[dev]"
```

## Install with the REST server

To also install the optional Flask-based REST server:

```bash
pip install "phileas-redact[server]"
```

See [REST Server](rest-server.md) for usage details.

## Verify the installation

```python
from phileas.services.filter_service import FilterService
from phileas.policy.policy import Policy

service = FilterService()
policy = Policy.from_dict({
    "name": "test",
    "identifiers": {
        "emailAddress": {
            "emailAddressFilterStrategies": [{"strategy": "REDACT"}]
        }
    }
})
result = service.filter(policy, "ctx", "doc-1", "hello@example.com")
print(result.filtered_text)  # {{{REDACTED-email-address}}}
```

## Building the documentation locally

The documentation uses [MkDocs](https://www.mkdocs.org/). Install MkDocs and serve the docs locally:

```bash
pip install mkdocs
mkdocs serve
```

Then open [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser.

To build a static site:

```bash
mkdocs build
```

The output is placed in the `site/` directory.
