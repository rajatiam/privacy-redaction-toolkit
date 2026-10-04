# Privacy Redaction Toolkit

Recursive structured-data redaction with auditable replacement counts. An independent Python 3.11+ project using the standard library, with a real command-line interface and no runtime package dependencies.

## Run locally

From the cloned repository, run:

```sh
python -m privacy_redaction_toolkit redact examples/events.json examples/redacted.json
python -m privacy_redaction_toolkit redact examples/events.json examples/redacted-stable.json --salt-file examples/demo-salt.txt
python -m privacy_redaction_toolkit --help
```

Examples contain synthetic data. First use requires no cloud account, API key or package download. Optionally install the CLI using `python -m pip install .` and run `privacy-redaction-toolkit --help`.

## Verify

```sh
python -m unittest discover -v
```

GitHub Actions checks Python 3.11 and 3.13 on Linux and Windows, verifies package installation, and builds/runs the non-root Docker image.

```sh
docker build -t privacy-redaction-toolkit .
docker run --rm privacy-redaction-toolkit --help
```

Mount a working directory at `/workspace` to process your own files. The container runs as UID 10001; provide appropriate write permissions for outputs.

## Architecture and scope

Business algorithms live in `privacy_redaction_toolkit/core.py`; `privacy_redaction_toolkit/cli.py` owns argument parsing and JSON output. Tests exercise success cases and failure boundaries, with temporary storage for mutations. See [design decisions](docs/architecture.md).

Recognizes configured sensitive keys, emails, IPv4 addresses and common bearer/token forms. Pattern detection cannot guarantee removal of all personal information. Optional HMAC pseudonyms allow correlation; keep the salt private.

This project demonstrates implemented engineering practices. It does not claim production deployment history or external certifications.

## Privacy exposure audit

Count recognized exposure categories without writing a redacted document or echoing source values. This is a scoped detector, not proof of anonymization.

```sh
python -m privacy_redaction_toolkit audit examples/events.json
```

Create the named input snapshots, databases or plan files first using the existing commands above.
