# Installation

## Requirements

- Python 3.11 or later
- [PyYAML](https://pypi.org/project/PyYAML/) (installed automatically as a dependency)
- The [`phisql`](https://github.com/philterd) package, which supplies the **catalog** of policy actions — the single source of truth for the available redaction strategies and the entity-type field mappings used by policies.

## The phisql catalog dependency

phileas now depends on the `phisql` package. The PhiSQL catalog defines every valid policy action (strategy) and the field names each entity type uses in a policy, so phileas reads them from the catalog rather than from hand-coded classes.

`phisql` is **not yet published on PyPI**, so for now it must be installed editable from a local checkout:

```bash
pip install -e /path/to/phisql/reference/python
```

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
