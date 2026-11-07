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
