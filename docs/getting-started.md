# Getting started

Requirements: Python 3.10 or newer. No third-party dependencies, no network.
On Debian/Ubuntu `python3 -m venv` needs the `python3-venv` package.

## Install from a clean checkout

```
git clone <URL-of-this-repository> security-reviewer
cd security-reviewer
python3 -m venv .venv
. .venv/bin/activate
pip install .
security-reviewer --help
```

Alternative without installing anything:

```
cd security-reviewer
PYTHONPATH=src python3 -m security_reviewer --help
```

The examples below use the installed command; prefix with
`PYTHONPATH=src python3 -m security_reviewer` if you did not install.

## Run the synthetic example

```
T=$(mktemp -d)    # scratch directory outside the repository
security-reviewer review examples/demo --timestamp 2026-01-02T03:04:05Z --output "$T/report.json"
echo $?        # 0
```

`examples/demo/` holds invented code: `join_vuln.py` (rule
`path-join-absolute-check-incomplete`), `tar_vuln.py` (rule
`tar-symlink-target-unchecked`) and `settings.py` (a placeholder-style
password literal, not a credential). The result must equal
[../examples/expected/review.json](../examples/expected/review.json):

```
cmp "$T/report.json" examples/expected/review.json && echo identical
```

Fail a CI job on any finding:

```
security-reviewer review examples/demo --fail-on-findings --output /dev/null; echo $?   # 1
```

Match an advisory separately (it never changes `findings`):

```
security-reviewer review examples/demo --timestamp 2026-01-02T03:04:05Z \
  --advisories examples/demo/advisories.json --package demo-pkg=1.0
```

Expected: [../examples/expected/review-advisory.json](../examples/expected/review-advisory.json).

Do not write reports for a real repository inside a tracked directory;
see the handling notes in [interpreting-results.md](interpreting-results.md).

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success (findings may exist) |
| 1 | Findings present and `--fail-on-findings` given |
| 2 | Usage or input error (bad flag, unreadable PATH, ...) |

The benchmark subcommand has its own table in [benchmark.md](benchmark.md).

## Next steps

- [interpreting-results.md](interpreting-results.md)
- [benchmark.md](benchmark.md) to reproduce the scoring harness
- [local-report.md](local-report.md) for the optional local model
- Run the tests: `python3 -m unittest discover -s tests -t .`
