# Source vulnerability detectors

`VulnScanner` (`security_reviewer.vuln_detectors`) is a `Scanner`: static,
offline, stdlib only, independent of any AI. It parses Python with `ast`
and never imports or executes scanned code. It reuses the symlink-safe
walker and limits of `SecretScanner`. It runs by default in
`security-reviewer review` (disable with `--no-vuln`).

Detectors match on code structure (calls, comparisons, branches), not on
project identifiers such as `safe_join` or `member`; renamed variables still
match. Findings are `schema_version` 1, `origin=static_tool`,
`status=hypothesis`, ids `vuln.<rule>.<hash16>`, with a short single-line
snippet (omitted if the line looks like it holds a secret) and remediation
text.

| Rule id | Detects | CWE | Severity | Confidence | Location |
| --- | --- | --- | --- | --- | --- |
| `path-join-absolute-check-incomplete` | A function that joins paths and guards a component with `isabs(x)` plus a `..` test, but never tests a leading `/` | CWE-22 | medium | medium | the `isabs` call |
| `tar-symlink-target-unchecked` | In a function with a loop, an `.issym()`/`.islnk()` branch that calls `_extract_member`/`extract`/`extractall` with no check relating `linkname` to the destination | CWE-22 | high | medium | the `if`/`elif` line of the branch |

Reference advisories: Werkzeug GHSA-f9vj-2wh5-fj8j (first rule), pip
GHSA-4xh5-x5gv-qwph (second rule).

Rule details:

- `path-join-absolute-check-incomplete` is suppressed when the function has
  no `join`/`joinpath`, when `..` is only a join argument rather than a test
  (`==`, `in`, `startswith`...), or when it does an explicit containment
  check (`commonpath`, `is_relative_to`, `relative_to`). A `/` constant or a
  `sep` attribute in an expression that uses the same variable counts as a
  leading-slash check.
- `tar-symlink-target-unchecked` does not fire on a bare `.issym()`
  classification, on a branch without extraction, on an extraction passing
  `filter=`, or when a condition before the extraction that relates to the
  link target (`linkname`, a variable derived from it, a helper whose name
  contains `link`, or a same-module helper reading `linkname`) leads to
  `raise`/`continue`/`return`/`break` or wraps the extraction. A guard inside a
  sibling link branch does not excuse another branch. The guard condition
  must also be a comparison or resolution (a call to `startswith`,
  `commonpath`, `realpath`, `is_relative_to`, `relative_to`, an in-archive
  `getmember`/`getnames` lookup, or a link-ish helper); a bare truth test
  such as `if not m.linkname: continue` is not a guard.

## Advisory matching is separate

Advisory matching (`--advisories`, `--package`) is a different mechanism: it
compares a declared version with a range and lists the result in
`advisory_matches`. It says nothing about the source, never changes
`findings`, and can be used with neither detector. See [cli.md](cli.md).

## Coverage and limitations

- Only Python is analysed. Other languages are counted
  (`coverage.unsupported.unsupported_language`); Python files that fail to
  parse (syntax errors, extreme nesting) are counted as `unparseable`, not
  errors. `coverage` is in the review report.
- Analysis is intra-file and intra-function with one-step name propagation:
  no cross-module data flow, no aliasing, no dynamic dispatch. Guards in
  other modules are invisible, so expect false positives; absent guards that
  use unusual spellings can cause false negatives.
- Guard heuristics are loose by design. For the path-join rule, any `/`
  constant or `sep`/`altsep` attribute in an expression sharing the variable
  counts as a leading-slash check, so `name.split('/')` suppresses a finding
  even though it does not reject a leading slash (false negative). For the
  tar rule, a guard whose condition merely calls a link-ish helper or the
  listed resolution calls counts, without proof it compares against the
  destination (false negative); the check position is by line number only.
- Work caps: a function (about 3M node visits) or file (about 6M) that
  exceeds the analysis budget is skipped and counted in
  `coverage.detector_skipped`; analysis is otherwise linear in function size.
- Two rules only. A clean report does not mean a repository is safe.
- Findings are hypotheses; there is no exploit reproduction.
