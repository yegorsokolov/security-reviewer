"""Defensive, source-based vulnerability detectors (no AI, no network).

Python files are parsed with :mod:`ast` and never imported or executed.
Detectors match on code *structure* (calls, guards, branches), not on
project-specific identifiers. Files that cannot be parsed are counted as
unsupported in :attr:`VulnScanner.coverage`; they are not errors.

Rules:

* ``path-join-absolute-check-incomplete`` (CWE-22)
* ``tar-symlink-target-unchecked`` (CWE-22)
"""
from __future__ import annotations

import ast
import hashlib
import warnings
from dataclasses import dataclass

from .finding import (
    _CTRL_RE, _SURROGATE_RE, Confidence, Evidence, EvidenceKind, Finding,
    Location, Origin, Remediation, Severity, Status,
)
from .secret_scanner import RULES as _SECRET_RULES
from .secret_scanner import ScanStats, SecretScanner

CATEGORY = "path-traversal"
CWE = "CWE-22"
ID_PREFIX = "vuln"
_SNIPPET_MAX = 160

_LANGUAGES = {
    ".py": "python", ".pyi": "python", ".js": "javascript",
    ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".go": "go",
    ".java": "java", ".kt": "kotlin", ".rb": "ruby", ".php": "php",
    ".rs": "rust", ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp",
    ".hpp": "cpp", ".cs": "csharp", ".sh": "shell", ".swift": "swift",
}


def language_of(path: str) -> str:
    dot = path.rfind(".")
    return _LANGUAGES.get(path[dot:].lower(), "other") if dot > 0 else "other"


# ------------------------------------------------------------ AST helpers
_FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef)
_LOOPS = (ast.For, ast.AsyncFor, ast.While, ast.ListComp, ast.SetComp,
          ast.DictComp, ast.GeneratorExp)


def _own_nodes(fn):
    """Nodes of ``fn`` excluding nested function bodies (iterative)."""
    stack = list(reversed(fn.body))
    while stack:
        n = stack.pop()
        yield n
        if isinstance(n, _FUNCS):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(n))))


def _functions(tree):
    return [n for n in ast.walk(tree) if isinstance(n, _FUNCS)]


def _names(node):
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _call_name(call):
    f = call.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return ""


def _str_consts(node):
    return [c.value for c in ast.walk(node)
            if isinstance(c, ast.Constant) and isinstance(c.value, str)]


# ------------------------------------------------- rule 1: absolute check
_TRAVERSAL_CONSTS = {"..", "../", "..\\"}
_CONTAINMENT_CALLS = {"commonpath", "is_relative_to", "relative_to"}


_TEST_CALLS = {"startswith", "endswith", "find", "index", "count"}


def _traversal_check(node):
    """A *test* for '..': a comparison/membership, or a prefix/suffix call.
    Merely passing '..' to join() is not a check."""
    if isinstance(node, ast.Compare):
        return any(s in _TRAVERSAL_CONSTS for s in _str_consts(node))
    if isinstance(node, ast.Call) and _call_name(node) in _TEST_CALLS:
        return any(s in _TRAVERSAL_CONSTS for a in node.args
                   for s in _str_consts(a))
    return False


def _leading_slash_check(node):
    """A reference to a '/' constant or a path separator attribute."""
    if "/" in _str_consts(node):
        return True
    return any(isinstance(n, ast.Attribute) and n.attr in ("sep", "altsep")
               for n in ast.walk(node))


def detect_path_join_absolute(tree):
    """Yield (line, col) of ``isabs(x)`` guards that miss a leading '/'."""
    for fn in _functions(tree):
        own = list(_own_nodes(fn))
        calls = [n for n in own if isinstance(n, ast.Call)]
        if not any(_call_name(c) in ("join", "joinpath") for c in calls):
            continue
        if any(_call_name(c) in _CONTAINMENT_CALLS for c in calls):
            continue
        probes = [n for n in own if isinstance(n, (ast.Compare, ast.Call))]
        for c in calls:
            if _call_name(c) != "isabs" or not c.args:
                continue
            argnames = _names(c.args[0])
            if not argnames:
                continue
            related = [p for p in probes if p is not c
                       and argnames & _names(p)]
            if not any(_traversal_check(p) for p in related):
                continue
            if any(_leading_slash_check(p) for p in related):
                continue
            yield c.lineno, c.col_offset + 1


# ------------------------------------------------- rule 2: tar symlinks
_LINK_TESTS = {"issym", "islnk"}
_EXTRACT_CALLS = {"_extract_member", "extract", "extractall"}
_EXIT = (ast.Raise, ast.Continue, ast.Return, ast.Break)


def _linkish_name(name):
    n = name.lower()
    return "link" in n and "unlink" not in n


def _helpers_using_linkname(tree):
    out = set()
    for fn in _functions(tree):
        if any(isinstance(n, ast.Attribute) and n.attr == "linkname"
               for n in _own_nodes(fn)):
            out.add(fn.name)
    return out


def _target_names(node):
    if isinstance(node, ast.Assign):
        return [t.id for t in node.targets if isinstance(t, ast.Name)]
    if isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
        t = node.target
        return [t.id] if isinstance(t, ast.Name) else []
    return []


def _related_fn(own, helpers):
    """Return a predicate: does an expression relate to a link target?"""
    link_vars: set = set()

    def related(expr):
        for n in ast.walk(expr):
            if isinstance(n, ast.Attribute) and n.attr == "linkname":
                return True
            if isinstance(n, ast.Call):
                nm = _call_name(n)
                if nm in helpers or _linkish_name(nm):
                    return True
            if isinstance(n, ast.Name) and n.id in link_vars:
                return True
        return False

    for _ in range(3):  # a few rounds of one-step propagation
        for n in own:
            if _target_names(n) and getattr(n, "value", None) is not None \
                    and related(n.value):
                link_vars.update(_target_names(n))
    return related


def _walk_stmts(stmts):
    for s in stmts:
        yield from ast.walk(s)


def detect_tar_symlink_unchecked(tree):
    """Yield (line, col) of symlink/hardlink branches that extract unchecked."""
    helpers = _helpers_using_linkname(tree)
    for fn in _functions(tree):
        own = list(_own_nodes(fn))
        if not any(isinstance(n, _LOOPS) for n in own):
            continue
        branches = [n for n in own if isinstance(n, ast.If) and any(
            isinstance(c, ast.Call) and _call_name(c) in _LINK_TESTS
            for c in ast.walk(n.test))]
        if not branches:
            continue
        related = _related_fn(own, helpers)
        body_ids = {id(b): {id(n) for n in _walk_stmts(b.body)}
                    for b in branches}
        for b in branches:
            ex = [c for c in _walk_stmts(b.body)
                  if isinstance(c, ast.Call)
                  and _call_name(c) in _EXTRACT_CALLS
                  and not any(k.arg == "filter" for k in c.keywords)]
            if not ex:
                continue
            ex_line = min(c.lineno for c in ex)
            if related(b.test):
                continue
            others = set()
            for o in branches:
                if o is not b:
                    others |= body_ids[id(o)] - body_ids[id(b)]
            if _guarded(own, others, related, ex, ex_line):
                continue
            yield b.lineno, b.col_offset + 1


def _guarded(own, excluded, related, ex, ex_line):
    ex_ids = {id(c) for c in ex}
    for n in own:
        if id(n) in excluded or getattr(n, "lineno", ex_line + 1) > ex_line:
            continue
        if isinstance(n, ast.Assert) and related(n.test):
            return True
        if isinstance(n, ast.If) and related(n.test):
            inner = list(_walk_stmts(n.body + n.orelse))
            if any(isinstance(x, _EXIT) for x in inner) \
                    or any(id(x) in ex_ids for x in inner):
                return True
    return False


# ------------------------------------------------------------------ rules
@dataclass(frozen=True)
class VulnRule:
    id: str
    title: str
    severity: Severity
    confidence: Confidence
    detect: object
    #: cheap text prefilter: the rule can only fire if any of these appear
    needs: tuple
    description: str
    remediation: str
    references: tuple


RULES = (
    VulnRule(
        "path-join-absolute-check-incomplete",
        "Path-join guard checks isabs() and '..' but not a leading '/'",
        Severity.MEDIUM, Confidence.MEDIUM, detect_path_join_absolute,
        ("isabs",),
        "A function validates untrusted path components with isabs() and a "
        "'..' check before joining them, but does not also reject a leading "
        "'/'. On platforms where isabs() does not treat '/x' as absolute "
        "(for example ntpath before Python 3.11) the join can escape the "
        "base directory.",
        "Also reject components that start with '/' (for example "
        "`filename.startswith(\"/\")`), or verify containment of the joined "
        "path with os.path.commonpath after normalisation.",
        ("https://cwe.mitre.org/data/definitions/22.html",
         "https://github.com/advisories/GHSA-f9vj-2wh5-fj8j")),
    VulnRule(
        "tar-symlink-target-unchecked",
        "Tar symlink/hardlink member extracted without checking its target",
        Severity.HIGH, Confidence.MEDIUM, detect_tar_symlink_unchecked,
        ("issym", "islnk"),
        "A branch that handles symlink or hardlink tar members extracts the "
        "member without any check relating the link target (linkname) to the "
        "extraction directory, so a crafted archive can create a link that "
        "points outside it.",
        "Validate the link target before extracting (resolve it relative to "
        "the member and require it to stay inside the destination), or use "
        "tarfile's filter=\"data\" where available.",
        ("https://cwe.mitre.org/data/definitions/22.html",
         "https://github.com/advisories/GHSA-4xh5-x5gv-qwph")),
)
RULE_IDS = tuple(r.id for r in RULES)
#: Registry consulted at scan time (rule id -> VulnRule).
DETECTORS = {r.id: r for r in RULES}


def _finding_id(rule_id, path, line, col):
    h = hashlib.sha256(f"{rule_id}\0{path}\0{line}\0{col}".encode(
        "utf-8", "surrogatepass")).hexdigest()[:16]
    return f"{ID_PREFIX}.{rule_id}.{h}"


def _snippet(line: str):
    s = _CTRL_RE.sub(" ", _SURROGATE_RE.sub("?", line)).strip()
    if any(True for r in _SECRET_RULES for _ in r.matches(s, True)):
        return None  # never echo a line that looks like it holds a secret
    return s[:_SNIPPET_MAX]


def _build(rule, path, line, col, lines):
    snip = _snippet(lines[line - 1]) if 0 < line <= len(lines) else None
    ev = [Evidence(EvidenceKind.TOOL_OUTPUT,
                   f"Rule {rule.id} matched structurally at line {line}.")]
    if snip:
        ev.append(Evidence(EvidenceKind.CODE_SNIPPET,
                           "Source line at the finding location.", snip))
    return Finding(
        id=_finding_id(rule.id, path, line, col), title=rule.title,
        category=CATEGORY, severity=rule.severity,
        confidence=rule.confidence, status=Status.HYPOTHESIS,
        origin=Origin.STATIC_TOOL,
        locations=(Location(path, line, line, col),),
        evidence=tuple(ev),
        remediation=Remediation(rule.remediation, None, rule.references),
        cwe=CWE, description=rule.description)


class VulnScanner(SecretScanner):
    """Scanner-compatible source detector. Reuses the hardened, symlink-safe
    walker and limits of :class:`SecretScanner`; only the per-file analysis
    differs. :attr:`coverage` describes what was analysed."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.coverage = _new_coverage()

    def scan(self, root):
        self.coverage = _new_coverage()
        self.coverage["rules_run"] = sorted(DETECTORS)
        return super().scan(root)

    def scan_text(self, path: str, text: str, stats: ScanStats | None = None):
        cov = self.coverage
        lang = language_of(path)
        cov["files_seen"][lang] = cov["files_seen"].get(lang, 0) + 1
        if lang != "python":
            cov["unsupported"]["unsupported_language"] += 1
            return
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                tree = ast.parse(text, filename="<scanned>")
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            cov["unsupported"]["unparseable"] += 1
            return
        cov["files_parsed"] += 1
        lines = text.split("\n")
        hits = []
        for rule in list(DETECTORS.values()):
            if not any(tok in text for tok in rule.needs):
                continue
            try:
                found = sorted(set(rule.detect(tree)))
            except RecursionError:
                cov["detector_errors"] += 1
                continue
            hits.extend((ln, col, rule) for ln, col in found)
        for ln, col, rule in sorted(hits, key=lambda h: (h[0], h[1], h[2].id)):
            yield _build(rule, path, ln, col, lines)


def _new_coverage():
    return {"rules_run": [], "files_seen": {}, "files_parsed": 0,
            "unsupported": {"unparseable": 0, "unsupported_language": 0},
            "detector_errors": 0}
