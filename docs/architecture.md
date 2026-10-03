# Privacy Redaction Toolkit: architecture

## Recursive filtering and scoped pseudonyms

Sensitive dictionary keys are replaced before traversing their values. Text patterns detect emails, valid IPv4 addresses and selected token formats. Optional HMAC-SHA256 pseudonyms support deterministic correlation, while replacement counts report categories without echoing removed values.

## Module boundaries

`privacy_redaction_toolkit/core.py` contains the algorithm and persistence operations. `cli.py` validates arguments and prints JSON. The package entrypoint translates input and storage errors into structured stderr with exit status 2. Domain-specific unsuccessful results can use exit status 1. There is no shared runtime dependency on the portfolio folder.

## Failure and operational boundaries

Pattern recognition is incomplete and is not a guarantee of anonymization. Pseudonym correlation intentionally leaks equality. Protect salt files and original/quarantined data. The committed example salt and credentials are synthetic public fixtures and must never be used for real data. Output is written separately and atomically.

## Verification

Core tests cover valid results and failure boundaries. Process-level CLI tests run the committed examples in temporary copies, inspect JSON output and verify domain outcomes. CI runs on Python 3.11 and 3.13, Linux and Windows, checks package installation, and builds and executes the non-root Docker image.

## Extension choices

The standard-library implementation keeps local execution inspectable and offline. A hosted or distributed version would require workload-specific authorization, resource limits, durable coordination and observability. Extend the core through tested functions rather than adding infrastructure without a scaling requirement.
