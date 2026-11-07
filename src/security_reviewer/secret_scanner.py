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
    ValidationMethod, _CTRL_RE, _SURROGATE_RE, _valid_path,
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

_PLACEHOLDER_TOKENS = frozenset({
    "change", "changeme", "me", "it", "changeit", "example", "placeholder",
    "your", "yours", "my", "the", "a", "api", "key", "token", "secret",
    "password", "passwd", "pass", "here", "dummy", "sample", "redacted",
    "todo", "fixme", "insert", "replace", "value", "test", "testing", "foo",
    "bar", "foobar", "string", "null", "none", "undefined", "notasecret",
    "xxx", "xxxx", "default", "demo", "fake", "mock", "secretkey",
})
_PLACEHOLDER_SHAPES = re.compile(
    r"<[^<>]*>|\$\{[^{}]*\}|\{\{[^{}]*\}\}|%[^%]+%|\$[a-z_][a-z0-9_]*"
    r"|[x*#._-]+|\.\.\.")


def _is_placeholder(value: str) -> bool:
    """Whole-value test only; substrings never make a value a placeholder."""
    v = value.lower()
    if _PLACEHOLDER_SHAPES.fullmatch(v) or len(set(v)) == 1:
        return True
    tokens = [t for t in re.split(r"[_.\-]+", v) if t]
    return bool(tokens) and all(t in _PLACEHOLDER_TOKENS for t in tokens)


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    confidence: Confidence
    regex: re.Pattern
    group: int = 0
    reject_placeholders: bool = False

    def matches(self, line: str, include_placeholders: bool = False):
        """Yield (start, end) spans (0-based, end exclusive) of the secret."""
        for m in self.regex.finditer(line):
            if (self.reject_placeholders and not include_placeholders
                    and _is_placeholder(m.group(self.group))):
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
             r"(?i)(?:password|passwd|pwd|secret(?:[_-]?access)?(?:[_-]?key)?"
             r"|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)"
             r"[\"']?\s{0,20}[:=]\s{0,20}[\"']([^\"'\s]{8,200})[\"']"),
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


_LONG_RUN = re.compile(r"[A-Za-z0-9+/=_-]{12,}")


def _redacted_snippet(line: str, truncated: bool, limit: int) -> str:
    """Text before the first secret-like match, then [REDACTED]. Nothing after
    a match is ever kept, and long token-like runs in the prefix are masked."""
    starts = [s for r in RULES for s, _ in r.matches(line, True)]
    prefix = line[:min(starts)] if starts else ""
    prefix = _LONG_RUN.sub(REDACTED, prefix)
    prefix = _CTRL_RE.sub(" ", _SURROGATE_RE.sub("?", prefix))
    return (prefix[-limit:].lstrip() + REDACTED)[:limit + len(REDACTED)]


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
        ) + (() if rule.id == "private-key" else (
            Evidence(EvidenceKind.CODE_SNIPPET,
                     "Text before the match; the rest is redacted.", snippet),
        )),
        remediation=REMEDIATION,
        cwe=CWE,
        description=("A value that looks like a hardcoded secret was found. "
                     "The value is intentionally not included in this finding."),
    )


def _secret_in(path: str) -> bool:
    """True if any secret rule matches the path (names must not leak secrets)."""
    return any(any(True for _ in r.matches(path, True)) for r in RULES)


def _read_regular(name, dfd, max_size, stats, rel=None):
    """Read a regular file relative to dir fd ``dfd`` without following links."""
    try:
        st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        if stat.S_ISLNK(st.st_mode):
            stats.skip("skipped_symlink", rel)
            return None
        if not stat.S_ISREG(st.st_mode):  # never open devices/FIFOs/sockets
            stats.skip("skipped_special", rel)
            return None
        flags = (os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                 | getattr(os, "O_CLOEXEC", 0))
        fd = os.open(name, flags, dir_fd=dfd)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                stats.skip("skipped_special", rel)
                return None
            if st.st_size > max_size:
                stats.skip("skipped_oversize", rel)
                return None
            chunks, total = [], 0
            while total <= max_size:
                c = os.read(fd, min(65536, max_size + 1 - total))
                if not c:
                    break
                chunks.append(c)
                total += len(c)
        finally:
            os.close(fd)
    except (OSError, ValueError):
        stats.skip("skipped_unreadable", rel)
        return None
    if total > max_size:
        stats.skip("skipped_oversize", rel)
        return None
    return b"".join(chunks)


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
    skipped_secret_in_path: int = 0
    entries_visited: int = 0
    hit_entry_cap: bool = False
    #: bounded sample of (reason, ascii-escaped path or None) for skips; the
    #: path is None when it looks like it contains a secret.
    skip_samples: list = field(default_factory=list)
    truncated_lines: int = 0
    hit_file_cap: bool = False
    hit_byte_cap: bool = False
    hit_finding_cap: bool = False

    MAX_SAMPLES = 50

    def skip(self, counter: str, path: str | None = None):
        setattr(self, counter, getattr(self, counter) + 1)
        if len(self.skip_samples) < self.MAX_SAMPLES:
            safe = None
            if path is not None and not _secret_in(path):
                safe = ascii(path)[:200]
            self.skip_samples.append((counter.removeprefix("skipped_"), safe))


class SecretScanner:
    """Implements :class:`~security_reviewer.interfaces.Scanner`."""

    def __init__(self, *, max_file_size: int = 1024 * 1024,
                 max_files: int = 10_000,
                 max_total_bytes: int = 64 * 1024 * 1024,
                 max_findings: int = 1_000,
                 max_line_length: int = 2_000,
                 max_entries: int = 200_000,
                 skip_dirs=DEFAULT_SKIP_DIRS):
        for name, v in (("max_file_size", max_file_size),
                        ("max_files", max_files),
                        ("max_total_bytes", max_total_bytes),
                        ("max_findings", max_findings),
                        ("max_line_length", max_line_length),
                        ("max_entries", max_entries)):
            if not isinstance(v, int) or isinstance(v, bool) or v < 1:
                raise ValueError(f"{name} must be a positive integer")
        self.max_file_size = max_file_size
        self.max_files = max_files
        self.max_total_bytes = max_total_bytes
        self.max_findings = max_findings
        self.max_line_length = max_line_length
        self.max_entries = max_entries
        self.skip_dirs = frozenset(skip_dirs)
        self.stats = ScanStats()

    # -- file system helpers
    def _walk(self, root: str, stats: ScanStats):
        """Yield (dir_fd, name, rel) sorted; symlinks and specials skipped.

        Uses fwalk(follow_symlinks=False) so entries are handled relative to
        open directory descriptors.
        """
        for dirpath, dirnames, filenames, dfd in os.fwalk(
                root, follow_symlinks=False):
            rel_dir = os.path.relpath(dirpath, root)
            rel_dir = "" if rel_dir == "." else rel_dir.replace(os.sep, "/") + "/"
            keep = []
            for d in sorted(dirnames):
                if stats.entries_visited >= self.max_entries:
                    stats.hit_entry_cap = True
                    dirnames[:] = []
                    return
                stats.entries_visited += 1
                if d in self.skip_dirs:
                    continue
                try:
                    is_link = stat.S_ISLNK(os.stat(
                        d, dir_fd=dfd, follow_symlinks=False).st_mode)
                except (OSError, ValueError):
                    stats.skip("skipped_unreadable")
                    continue
                if is_link:
                    stats.skip("skipped_symlink", rel_dir + d)
                elif _secret_in(d):
                    stats.skip("skipped_secret_in_path")
                else:
                    keep.append(d)
            dirnames[:] = keep
            for fn in sorted(filenames):
                if stats.entries_visited >= self.max_entries:
                    stats.hit_entry_cap = True
                    return
                stats.entries_visited += 1
                yield dfd, fn, rel_dir + fn

    def _read(self, name: str, dfd: int, stats: ScanStats,
              rel: str | None = None) -> bytes | None:
        return _read_regular(name, dfd, self.max_file_size, stats, rel)

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
        for dfd, name, rel in self._walk(root, stats):
            if stats.findings >= self.max_findings:
                stats.hit_finding_cap = True
                return
            if stats.files_scanned >= self.max_files:
                stats.hit_file_cap = True
                return
            if len(rel) > MAX_PATH or not _valid_path(rel) \
                    or _SURROGATE_RE.search(rel):
                stats.skip("skipped_bad_path", rel)
                continue
            if _secret_in(rel):
                stats.skip("skipped_secret_in_path")
                continue
            data = self._read(name, dfd, stats, rel)
            if data is None:
                continue
            if stats.bytes_read + len(data) > self.max_total_bytes:
                stats.hit_byte_cap = True
                return
            stats.files_scanned += 1
            stats.bytes_read += len(data)
            if b"\x00" in data:
                stats.skip("skipped_binary", rel)
                continue
            for f in self.scan_text(rel, _to_text(data), stats):
                try:  # path may be invalid for the format (odd characters)
                    Finding.from_dict(f.to_dict())
                except ValidationError:
                    stats.skip("skipped_bad_path", rel)
                    break
                stats.findings += 1
                yield f
                if stats.findings >= self.max_findings:
                    stats.hit_finding_cap = True
                    return


class LocalContextReader:
    """ContextReader over a directory root. Each directory component is opened
    with O_NOFOLLOW|O_DIRECTORY relative to its parent descriptor, and the file
    with O_NOFOLLOW, so symlinks are refused at every step."""

    def __init__(self, root, *, max_file_size: int = 1024 * 1024):
        self.root = os.fspath(root)
        self.max_file_size = max_file_size

    def __call__(self, path: str) -> str | None:
        if (not isinstance(path, str) or len(path) > MAX_PATH
                or _SURROGATE_RE.search(path) or not _valid_path(path)):
            return None
        parts = path.split("/")
        fds = []
        try:
            cur = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY
                          | getattr(os, "O_CLOEXEC", 0))
            fds.append(cur)
            for p in parts[:-1]:
                cur = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                              | getattr(os, "O_CLOEXEC", 0), dir_fd=cur)
                fds.append(cur)
            data = _read_regular(parts[-1], cur, self.max_file_size, ScanStats())
        except (OSError, ValueError):
            return None
        finally:
            for fd in fds:
                os.close(fd)
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
