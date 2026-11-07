"""Local, stdlib-only hardcoded-secret scanner and matching validator.

Scanned files are untrusted: they are only ever read as bytes and decoded
with errors="replace"; never imported, executed or followed through symlinks.
No finding field ever contains a full secret value.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .finding import (
    MAX_PATH, Confidence, Evidence, EvidenceKind, Finding, Location, Origin,
    Remediation, Severity, Status, Validation, ValidationError,
    ValidationMethod, _CTRL_RE, _SURROGATE_RE,
)

CATEGORY = "hardcoded-secret"
CWE = "CWE-798"
VALIDATOR_NAME = "security_reviewer.SecretValidator"
REDACTED = "[REDACTED]"

DEFAULT_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "vendor", "third_party",
    "bower_components", ".venv", "venv", "__pycache__", ".tox",
    ".mypy_cache", "site-packages",
})

_PLACEHOLDER_WORDS = (
    "changeme", "change_me", "example", "placeholder", "your", "dummy",
    "sample", "xxxx", "redacted", "todo", "fixme", "insert", "replace",
    "password", "secret", "notasecret", "foobar", "*****",
)


def _is_placeholder(value: str) -> bool:
    v = value.lower()
    if v[0] in "<{$%[" or v.startswith(("${", "{{", "<%")):
        return True
    if len(set(v)) <= 2:
        return True
    return any(w in v for w in _PLACEHOLDER_WORDS)


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    confidence: Confidence
    regex: re.Pattern
    group: int = 0
    reject_placeholders: bool = False

    def matches(self, line: str):
        """Yield (start, end) spans (0-based, end exclusive) of the secret."""
        for m in self.regex.finditer(line):
            if self.reject_placeholders and _is_placeholder(m.group(self.group)):
                continue
            yield m.start(self.group), m.end(self.group)


RULES = (
    Rule("aws-access-key-id", "AWS access key ID in source", Severity.HIGH,
         Confidence.MEDIUM, re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])")),
    Rule("private-key", "Private key material in source", Severity.HIGH,
         Confidence.MEDIUM, re.compile(
             r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?"
             r"PRIVATE KEY(?: BLOCK)?-----")),
    Rule("github-token", "GitHub token in source", Severity.HIGH,
         Confidence.MEDIUM, re.compile(
             r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,255}"
             r"|github_pat_[A-Za-z0-9_]{22,255})(?![A-Za-z0-9_])")),
    Rule("slack-token", "Slack token in source", Severity.HIGH,
         Confidence.MEDIUM, re.compile(
             r"(?<![A-Za-z0-9])xox[abprs]-[0-9A-Za-z-]{10,200}")),
    Rule("generic-credential", "Hardcoded credential assignment",
         Severity.MEDIUM, Confidence.LOW, re.compile(
             r"(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?token)"
             r"[\"']?\s*[:=]\s*[\"']([^\"'\s]{8,200})[\"']"),
         group=1, reject_placeholders=True),
)
_RULES_BY_ID = {r.id: r for r in RULES}

REMEDIATION = Remediation(
    "Treat the credential as compromised: rotate or revoke it at the issuer, "
    "remove it from the source (and purge it from git history), and load it "
    "from an environment variable or a secret manager instead.",
    None,
    ("https://cwe.mitre.org/data/definitions/798.html",),
)


def _rule_from_id(fid: str):
    parts = fid.split(".")
    if len(parts) == 3 and parts[0] == "secret":
        return _RULES_BY_ID.get(parts[1])
    return None


def _finding_id(rule: Rule, path: str, line_no: int, col: int) -> str:
    # Hash of location only; never of the secret value.
    h = hashlib.sha256(f"{rule.id}\0{path}\0{line_no}\0{col}".encode(
        "utf-8", "surrogatepass")).hexdigest()[:16]
    return f"secret.{rule.id}.{h}"


def _redacted_snippet(line: str, truncated: bool, limit: int) -> str:
    # Every real match of any rule on the line is redacted (placeholder values
    # are not secrets and stay visible). Redact first, trim afterwards.
    spans = sorted(s for r in RULES for s in r.matches(line))
    out, pos = [], 0
    for s, e in spans:
        if e <= pos:
            continue
        out.append(line[pos:max(s, pos)])
        out.append(REDACTED)
        pos = e
    out.append(line[pos:])
    text = "".join(out)
    if truncated:  # a secret may straddle the cut; drop the tail
        text = text[:max(0, len(text) - 64)]
    text = _CTRL_RE.sub(" ", _SURROGATE_RE.sub("?", text)).strip()
    return text[:limit]


def _to_text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _build_finding(rule, path, line_no, start, end, line, truncated, limit):
    col = start + 1
    snippet = _redacted_snippet(line, truncated, limit)
    return Finding(
        id=_finding_id(rule, path, line_no, col),
        title=rule.title,
        category=CATEGORY,
        severity=rule.severity,
        confidence=rule.confidence,
        status=Status.HYPOTHESIS,
        origin=Origin.STATIC_TOOL,
        locations=(Location(path, line_no, line_no, col, max(col, end)),),
        evidence=(
            Evidence(EvidenceKind.TOOL_OUTPUT,
                     f"Rule {rule.id} matched at line {line_no}; "
                     "secret value redacted."),
            Evidence(EvidenceKind.CODE_SNIPPET,
                     "Matching line with secret value redacted.", snippet),
        ),
        remediation=REMEDIATION,
        cwe=CWE,
        description=("A value that looks like a hardcoded secret was found. "
                     "The value is intentionally not included in this finding."),
    )


@dataclass
class ScanStats:
    files_scanned: int = 0
    bytes_read: int = 0
    findings: int = 0
    skipped_symlink: int = 0
    skipped_oversize: int = 0
    skipped_binary: int = 0
    skipped_unreadable: int = 0
    skipped_bad_path: int = 0
    skipped_special: int = 0
    truncated_lines: int = 0
    hit_file_cap: bool = False
    hit_byte_cap: bool = False
    hit_finding_cap: bool = False


class SecretScanner:
    """Implements :class:`~security_reviewer.interfaces.Scanner`."""

    def __init__(self, *, max_file_size: int = 1024 * 1024,
                 max_files: int = 10_000,
                 max_total_bytes: int = 64 * 1024 * 1024,
                 max_findings: int = 1_000,
                 max_line_length: int = 2_000,
                 skip_dirs=DEFAULT_SKIP_DIRS):
        for name, v in (("max_file_size", max_file_size),
                        ("max_files", max_files),
                        ("max_total_bytes", max_total_bytes),
                        ("max_findings", max_findings),
                        ("max_line_length", max_line_length)):
            if not isinstance(v, int) or isinstance(v, bool) or v < 1:
                raise ValueError(f"{name} must be a positive integer")
        self.max_file_size = max_file_size
        self.max_files = max_files
        self.max_total_bytes = max_total_bytes
        self.max_findings = max_findings
        self.max_line_length = max_line_length
        self.skip_dirs = frozenset(skip_dirs)
        self.stats = ScanStats()

    # -- file system helpers
    def _walk(self, root: str, stats: ScanStats) -> Iterator[tuple[str, str]]:
        """Yield (absolute path, repo-relative POSIX path), sorted, no symlinks."""
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            keep = []
            for d in sorted(dirnames):
                if d in self.skip_dirs:
                    continue
                if os.path.islink(os.path.join(dirpath, d)):
                    stats.skipped_symlink += 1
                    continue
                keep.append(d)
            dirnames[:] = keep
            for fn in sorted(filenames):
                full = os.path.join(dirpath, fn)
                if os.path.islink(full):
                    stats.skipped_symlink += 1
                    continue
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                yield full, rel

    def _read(self, full: str, stats: ScanStats) -> bytes | None:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) \
            | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(full, flags)
        except OSError:
            stats.skipped_unreadable += 1
            return None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                stats.skipped_special += 1
                return None
            if st.st_size > self.max_file_size:
                stats.skipped_oversize += 1
                return None
            with os.fdopen(fd, "rb", closefd=False) as fh:
                data = fh.read(self.max_file_size + 1)
        except OSError:
            stats.skipped_unreadable += 1
            return None
        finally:
            os.close(fd)
        if len(data) > self.max_file_size:
            stats.skipped_oversize += 1
            return None
        return data

    def _snippet_limit(self) -> int:
        return min(200, max(20, self.max_line_length // 2))

    def scan_text(self, path: str, text: str, stats: ScanStats | None = None):
        """Yield findings for already-decoded ``text`` of repo path ``path``."""
        stats = stats or ScanStats()
        for n, raw in enumerate(text.split("\n"), 1):
            line = raw.rstrip("\r")
            truncated = len(line) > self.max_line_length
            if truncated:
                stats.truncated_lines += 1
                line = line[:self.max_line_length]
            if not line:
                continue
            for rule in RULES:
                for s, e in rule.matches(line):
                    yield _build_finding(rule, path, n, s, e, line, truncated,
                                         self._snippet_limit())

    # -- Scanner protocol
    def scan(self, root) -> Iterator[Finding]:
        root = os.fspath(root)
        if not os.path.isdir(root):
            raise ValueError("root must be an existing directory")
        self.stats = stats = ScanStats()
        for full, rel in self._walk(root, stats):
            if stats.findings >= self.max_findings:
                stats.hit_finding_cap = True
                return
            if stats.files_scanned >= self.max_files:
                stats.hit_file_cap = True
                return
            if len(rel) > MAX_PATH:
                stats.skipped_bad_path += 1
                continue
            data = self._read(full, stats)
            if data is None:
                continue
            if stats.bytes_read + len(data) > self.max_total_bytes:
                stats.hit_byte_cap = True
                return
            stats.files_scanned += 1
            stats.bytes_read += len(data)
            if b"\x00" in data:
                stats.skipped_binary += 1
                continue
            for f in self.scan_text(rel, _to_text(data), stats):
                try:  # path may be invalid for the format (odd characters)
                    Finding.from_dict(f.to_dict())
                except ValidationError:
                    stats.skipped_bad_path += 1
                    break
                stats.findings += 1
                yield f
                if stats.findings >= self.max_findings:
                    stats.hit_finding_cap = True
                    return


class LocalContextReader:
    """ContextReader over a directory root; same safety rules as the scanner."""

    def __init__(self, root, *, max_file_size: int = 1024 * 1024):
        self.root = os.path.realpath(os.fspath(root))
        self._scanner = SecretScanner(max_file_size=max_file_size)

    def __call__(self, path: str) -> str | None:
        parts = path.split("/")
        if not path or path.startswith("/") or any(
                p in ("", ".", "..") for p in parts) or "\\" in path:
            return None
        cur = self.root
        for p in parts[:-1]:  # refuse any symlinked directory component
            cur = os.path.join(cur, p)
            if os.path.islink(cur):
                return None
        data = self._scanner._read(os.path.join(cur, parts[-1]), ScanStats())
        if data is None or b"\x00" in data:
            return None
        return _to_text(data)


class SecretValidator:
    """Implements Validator: re-checks a secret finding against the file."""

    def __init__(self, clock=None):
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def validate(self, finding: Finding, reader) -> Finding | None:
        rule = _rule_from_id(finding.id)
        if (rule is None or finding.origin is not Origin.STATIC_TOOL
                or finding.status is not Status.HYPOTHESIS
                or finding.category != CATEGORY or not finding.locations):
            return None
        loc = finding.locations[0]
        text = reader(loc.path)
        if text is None:
            return None
        lines = text.split("\n")
        if loc.start_line > len(lines):
            return None
        line = lines[loc.start_line - 1].rstrip("\r")
        want = (loc.start_column or 1) - 1
        if not any(s == want for s, _ in rule.matches(line)):
            return None
        ts = self._clock().astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            return finding.transition(Status.VALIDATED, Validation(
                ValidationMethod.TOOL_CONFIRMED, VALIDATOR_NAME, ts,
                "Pattern re-matched at the recorded location; this does not "
                "prove the credential is live."))
        except ValidationError:
            return None
