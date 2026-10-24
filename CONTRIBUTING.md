# Contributing

Open an issue with the concrete scenario and a minimal synthetic input before
proposing a broad feature. Keep runtime dependencies and network access out of
the core. Do not attach private exports, source snippets, or credentials.

Use Python 3.11 or newer:

```console
python -m venv .venv
python -m pip install -e . -r requirements-dev.txt
python -m ruff check .
python -m ruff format --check .
python -m coverage run -m unittest discover -s tests -v
python -m coverage report
python -m build
python scripts/verify_install.py
```

Activate the virtual environment before installing. On PowerShell use
`.venv\Scripts\Activate.ps1`; on POSIX use `. .venv/bin/activate`.
Tests must demonstrate a failure as well as a successful core workflow.
CI only tests and builds; it never commits, updates dependencies, or publishes.
The owner applies reviewed changes under the repository's commit identity.
