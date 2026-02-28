# Publishing to PyPI

This document provides instructions for publishing the phileas package to PyPI.

## Prerequisites

1. **Install build tools:**
   ```bash
   pip install --upgrade build twine
   ```

2. **PyPI account:**
   - Create an account at https://pypi.org/account/register/
   - Generate an API token at https://pypi.org/manage/account/token/

3. **TestPyPI account (recommended for testing):**
   - Create an account at https://test.pypi.org/account/register/
   - Generate an API token at https://test.pypi.org/manage/account/token/

## Pre-publication Checklist

- [x] Package metadata complete in `pyproject.toml`
  - [x] Name, version, description
  - [x] Author and maintainer information
  - [x] License (Apache-2.0)
  - [x] Python version requirement (>=3.9)
  - [x] Keywords and classifiers
  - [x] Project URLs
- [x] All Python source files have Apache license headers
- [x] README.md is comprehensive and up-to-date
- [x] LICENSE file present
- [x] MANIFEST.in includes necessary files
- [x] Package discovery configured correctly
- [x] Package data files included (CSV resources)
- [x] Console scripts defined (phileas, phileas-server)
- [ ] All tests passing
- [ ] Documentation built and accessible
- [ ] Version number updated

## Build the Package

1. **Clean previous builds:**
   ```bash
   rm -rf dist/ build/ *.egg-info
   ```

2. **Build the package:**
   ```bash
   python -m build
   ```

   This creates:
   - `dist/phileas-<version>.tar.gz` (source distribution)
   - `dist/phileas-<version>-py3-none-any.whl` (wheel distribution)

3. **Verify the build:**
   ```bash
   tar -tzf dist/phileas-*.tar.gz | head -20
   unzip -l dist/phileas-*.whl | head -20
   ```

   Check that all expected files are present:
   - All Python modules
   - `phileas/resources/zip-code-population.csv`
   - `README.md`
   - `LICENSE`

## Test with TestPyPI (Recommended)

1. **Upload to TestPyPI:**
   ```bash
   python -m twine upload --repository testpypi dist/*
   ```

   When prompted, use `__token__` as username and your TestPyPI API token as password.

2. **Test installation from TestPyPI:**
   ```bash
   pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ phileas-redact
   ```

3. **Test the installation:**
   ```bash
   python -c "from phileas import FilterService, Policy; print('✓ Import successful')"
   phileas --help
   ```

## Publish to PyPI

1. **Upload to PyPI:**
   ```bash
   python -m twine upload dist/*
   ```

   When prompted, use `__token__` as username and your PyPI API token as password.

2. **Verify the upload:**
   - Visit https://pypi.org/project/phileas-redact/
   - Check that metadata is correct
   - Verify README renders properly

3. **Test installation:**
   ```bash
   pip install phileas-redact
   python -c "from phileas import FilterService; print('✓ Installed successfully')"
   ```

## Post-publication

1. **Tag the release in git:**
   ```bash
   git tag -a v1.0.0 -m "Release version 1.0.0"
   git push origin v1.0.0
   ```

2. **Create a GitHub release:**
   - Go to https://github.com/philterd/phileas-python/releases
   - Create a new release from the tag
   - Add release notes

3. **Update documentation:**
   - Ensure docs site is updated
   - Update any version references

## Using API Tokens (Recommended)

Instead of entering credentials each time, configure your API tokens:

1. **Create `~/.pypirc`:**
   ```ini
   [distutils]
   index-servers =
       pypi
       testpypi

   [pypi]
   username = __token__
   password = pypi-AgEIcHlwaS5vcmc...

   [testpypi]
   repository = https://test.pypi.org/legacy/
   username = __token__
   password = pypi-AgENdGVzdC5weXBpLm9yZw...
   ```

2. **Set file permissions:**
   ```bash
   chmod 600 ~/.pypirc
   ```

## Troubleshooting

### Missing files in distribution
- Check MANIFEST.in
- Verify package-data in pyproject.toml
- Rebuild and inspect with `tar -tzf` or `unzip -l`

### Import errors after installation
- Verify all `__init__.py` files are present
- Check package discovery configuration
- Test in a fresh virtual environment

### Upload errors
- Ensure version number hasn't been used before
- Check API token is valid and has upload permissions
- Verify package name is available (not taken)

### README not rendering
- Validate Markdown syntax
- Check that `readme = "README.md"` is in pyproject.toml
- Test with `python -m readme_renderer README.md`

## Package Metadata Summary

Current configuration:
- **Name:** phileas-redact
- **Version:** 1.0.0
- **License:** Apache-2.0
- **Python:** >=3.9
- **Dependencies:** PyYAML>=6.0
- **Optional:** dev (pytest, mkdocs), server (flask)
- **Scripts:** phileas, phileas-server
