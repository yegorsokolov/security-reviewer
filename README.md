# security-reviewer
Open-source AI security reviewer that detects, validates, explains, and prioritizes vulnerabilities in GitHub repositories.

## Scanning for hardcoded secrets

```python
from security_reviewer import SecretScanner

for finding in SecretScanner().scan("path/to/checkout"):
    print(finding.to_json())  # schema_version 1, secret values redacted
```

See [docs/scanner.md](docs/scanner.md) for the `Scanner`/`Validator`
interfaces, rules and safety limits, and
[docs/finding-format.md](docs/finding-format.md) for the finding format.

## Command line

```
PYTHONPATH=src python3 -m security_reviewer review PATH
```

Offline, deterministic JSON output; see [docs/cli.md](docs/cli.md).

## Source vulnerability detectors and benchmark

`review` also runs AI-independent source detectors, and reports advisory
matches separately. See [docs/detectors.md](docs/detectors.md) and the
scoring harness in [docs/benchmark.md](docs/benchmark.md).
