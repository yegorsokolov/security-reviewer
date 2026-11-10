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


# ------------------------------------------------------------ work caps
#: Per-function and per-file work caps (roughly "AST nodes visited"). A
#: function or file that exceeds them is skipped and counted under
#: ``coverage["detector_skipped"]``; it is never an error.
MAX_FUNCTION_WORK = 3_000_000
MAX_FILE_WORK = 6_000_000


class _OverBudget(Exception):
    pass


class _Work:
    """Work accounting shared by all detectors for one file."""

    def __init__(self, function_cap=None, file_cap=None):
        self.function_cap = function_cap or MAX_FUNCTION_WORK
        self.file_left = file_cap or MAX_FILE_WORK
        self.fn_left = function_cap
        self.skipped = 0

    def begin_function(self):
        self.fn_left = self.function_cap
        self.charge(0)

    def charge(self, n):
        self.fn_left -= n
        self.file_left -= n
        if self.fn_left < 0 or self.file_left < 0:
            raise _OverBudget

    def nodes(self, node):
        out = list(ast.walk(node))
        self.charge(len(out))
        return out

    def nodes_of(self, stmts):
        out = list(_walk_stmts(stmts))
        self.charge(len(out))
        return out

    def own(self, fn):
        out = list(_own_nodes(fn))
        self.charge(len(out))
        return out


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


def _path_join_function(fn, work):
    own = work.own(fn)
    calls = [n for n in own if isinstance(n, ast.Call)]
    if not any(_call_name(c) in ("join", "joinpath") for c in calls):
        return []
    if any(_call_name(c) in _CONTAINMENT_CALLS for c in calls):
        return []
    isabs = [c for c in calls if _call_name(c) == "isabs" and c.args]
    if not isabs:
        return []
    # One pass over the probes: per-name counts of probes that test '..'
    # and probes that mention a leading slash. Each probe is walked once.
    trav_by_name: dict = {}
    slash_by_name: dict = {}
    info: dict = {}
    for p in own:
        if not isinstance(p, (ast.Compare, ast.Call)):
            continue
        nodes = work.nodes(p)
        names, strs, slash = set(), set(), False
        for n in nodes:  # one walk: names, string constants, '/' or sep
            if isinstance(n, ast.Name):
                names.add(n.id)
            elif isinstance(n, ast.Constant) and isinstance(n.value, str):
                strs.add(n.value)
            elif isinstance(n, ast.Attribute) and n.attr in ("sep", "altsep"):
                slash = True
        if not names:
            continue
        slash = slash or "/" in strs
        if isinstance(p, ast.Compare):
            trav = bool(strs & _TRAVERSAL_CONSTS)
        else:
            trav = _traversal_check(p) if _call_name(p) in _TEST_CALLS \
                else False
        info[id(p)] = (trav, slash)
        for nm in names:
            if trav:
                trav_by_name[nm] = trav_by_name.get(nm, 0) + 1
            if slash:
                slash_by_name[nm] = slash_by_name.get(nm, 0) + 1
    out = []
    for c in isabs:
        argnames = {n.id for n in work.nodes(c.args[0])
                    if isinstance(n, ast.Name)}
        if not argnames:
            continue
        self_trav, self_slash = info[id(c)]  # c mentions all of argnames
        if not any(trav_by_name.get(n, 0) - self_trav > 0 for n in argnames):
            continue
        if any(slash_by_name.get(n, 0) - self_slash > 0 for n in argnames):
            continue
        out.append((c.lineno, c.col_offset + 1))
    return out


def detect_path_join_absolute(tree, work=None):
    """Yield (line, col) of ``isabs(x)`` guards that miss a leading '/'."""
    work = work or _Work()
    for fn in _functions(tree):
        try:
            work.begin_function()
            found = _path_join_function(fn, work)
        except _OverBudget:
            work.skipped += 1
            continue
        yield from found


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


_RESOLVE_CALLS = {"startswith", "commonpath", "realpath", "is_relative_to",
                  "relative_to", "getmember", "getnames", "getmembers"}


def _related_fn(own, helpers, work):
    """Return (related, strong) predicates over expressions.

    ``related``: does an expression involve a link target (linkname, a
    variable derived from it, a link-ish helper)? ``strong``: is it also a
    real comparison/resolution (prefix/containment/realpath call, an
    in-archive lookup, or a link-ish helper call) rather than a bare truth
    test such as ``if not m.linkname``?"""
    link_vars: set = set()

    def related(expr):
        for n in work.nodes(expr):
            if isinstance(n, ast.Attribute) and n.attr == "linkname":
                return True
            if isinstance(n, ast.Call):
                nm = _call_name(n)
                if nm in helpers or _linkish_name(nm):
                    return True
            if isinstance(n, ast.Name) and n.id in link_vars:
                return True
        return False

    def strong(expr):
        for n in work.nodes(expr):
            if isinstance(n, ast.Call):
                nm = _call_name(n)
                if nm in _RESOLVE_CALLS or nm in helpers \
                        or _linkish_name(nm):
                    return True
        return False

    for _ in range(3):  # a few rounds of one-step propagation
        for n in own:
            if _target_names(n) and getattr(n, "value", None) is not None \
                    and related(n.value):
                link_vars.update(_target_names(n))
    return related, lambda e: related(e) and strong(e)


def _walk_stmts(stmts):
    for s in stmts:
        yield from ast.walk(s)


def _extract_calls(nodes):
    return [c for c in nodes if isinstance(c, ast.Call)
            and _call_name(c) in _EXTRACT_CALLS
            and not any(k.arg == "filter" for k in c.keywords)]


def _tar_function(fn, work, helpers):
    own = work.own(fn)
    if not any(isinstance(n, _LOOPS) for n in own):
        return []
    branches = []
    for n in own:
        if isinstance(n, ast.If) and any(
                isinstance(c, ast.Call) and _call_name(c) in _LINK_TESTS
                for c in work.nodes(n.test)):
            branches.append(n)
    if not branches:
        return []
    work.charge(3 * len(own))
    related, guard_test = _related_fn(own, helpers, work)

    # Guards, computed once per function: (line, node id, unconditional,
    # extract-call ids it wraps). Unconditional = asserts and Ifs that exit.
    guards = {}
    wrappers: dict = {}
    for n in own:
        if isinstance(n, ast.Assert) and guard_test(n.test):
            guards[id(n)] = (n.lineno, id(n), True)
        elif isinstance(n, ast.If) and guard_test(n.test):
            inner = work.nodes_of(n.body + n.orelse)
            if any(isinstance(x, _EXIT) for x in inner):
                guards[id(n)] = (n.lineno, id(n), True)
            else:
                g = (n.lineno, id(n), False)
                guards[id(n)] = g
                for c in _extract_calls(inner):
                    wrappers.setdefault(id(c), []).append(g)

    # Union of all branch bodies, built once: cover[id] = number of branches
    # whose body contains the node. A node is excluded for branch b iff it
    # is covered and not inside b's own body (i.e. it is in a sibling's).
    body_ids, body_ex, guards_in, cover = {}, {}, {}, {}
    for b in branches:
        nodes = work.nodes_of(b.body)
        ids = {id(x) for x in nodes}
        body_ids[id(b)] = ids
        body_ex[id(b)] = _extract_calls(nodes)
        guards_in[id(b)] = [guards[i] for i in ids if i in guards]
        for i in ids:
            cover[i] = cover.get(i, 0) + 1
    free_min = min((g[0] for i, g in guards.items()
                    if g[2] and i not in cover), default=None)

    out = []
    for b in branches:
        ex = body_ex[id(b)]
        if not ex:
            continue
        ex_line = min(c.lineno for c in ex)
        if related(b.test):
            continue
        mine = body_ids[id(b)]
        if free_min is not None and free_min <= ex_line:
            continue
        if any(g[2] and g[0] <= ex_line for g in guards_in[id(b)]):
            continue
        if any(g[0] <= ex_line and (g[1] not in cover or g[1] in mine)
               for c in ex for g in wrappers.get(id(c), ())):
            continue
        out.append((b.lineno, b.col_offset + 1))
    return out


def detect_tar_symlink_unchecked(tree, work=None):
    """Yield (line, col) of symlink/hardlink branches that extract unchecked."""
    work = work or _Work()
    helpers = _helpers_using_linkname(tree)
    for fn in _functions(tree):
        try:
            work.begin_function()
            found = _tar_function(fn, work, helpers)
        except _OverBudget:
            work.skipped += 1
            continue
        yield from found


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
        work = _Work()
        for rule in list(DETECTORS.values()):
            if not any(tok in text for tok in rule.needs):
                continue
            try:
                found = sorted(set(rule.detect(tree, work)))
            except RecursionError:
                cov["detector_errors"] += 1
                continue
            hits.extend((ln, col, rule) for ln, col in found)
        cov["detector_skipped"] += work.skipped
        for ln, col, rule in sorted(hits, key=lambda h: (h[0], h[1], h[2].id)):
            yield _build(rule, path, ln, col, lines)


def _new_coverage():
    return {"rules_run": [], "files_seen": {}, "files_parsed": 0,
            "unsupported": {"unparseable": 0, "unsupported_language": 0},
            "detector_errors": 0, "detector_skipped": 0}
