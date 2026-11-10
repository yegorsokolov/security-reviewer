"""Advisory matching, kept separate from source detection.

Advisories come from a local JSON file; matching compares a declared package
version with an affected range. Results are reported in their own list and
never change any source finding. Stdlib only, no network.
"""
from __future__ import annotations

import json
import re

_INF = float("inf")
_PRE_RANK = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2,
             "pre": 2, "preview": 2}
_VERSION_RE = re.compile(
    r"v?(?:(?P<epoch>\d+)!)?(?P<rel>\d+(?:\.\d+)*)"
    r"(?:[-_.]?(?P<pre>alpha|beta|preview|pre|rc|a|b|c)[-_.]?(?P<pren>\d*))?"
    r"(?:-(?P<post1>\d+)|[-_.]?(?P<postl>post|rev|r)[-_.]?(?P<post2>\d*))?"
    r"(?:[-_.]?(?P<devl>dev)[-_.]?(?P<dev>\d*))?"
    r"(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?", re.IGNORECASE)
_CLAUSE_RE = re.compile(r"\s*(<=|>=|==|!=|<|>)\s*(\S+)\s*")
MAX_FIELD = 200


class AdvisoryError(ValueError):
    """Invalid version, range or advisory file."""


def parse_version(text):
    """Return a sortable key for a PEP 440-style version (local part ignored)."""
    if not isinstance(text, str) or len(text) > 64:
        raise AdvisoryError("invalid version")
    m = _VERSION_RE.fullmatch(text.strip())
    if not m:
        raise AdvisoryError("invalid version")
    rel = [int(x) for x in m["rel"].split(".")]
    while len(rel) > 1 and rel[-1] == 0:
        rel.pop()
    pre = (_PRE_RANK[m["pre"].lower()], int(m["pren"] or 0)) \
        if m["pre"] else None
    post = None
    if m["post1"] is not None:
        post = int(m["post1"])
    elif m["postl"]:
        post = int(m["post2"] or 0)
    dev = int(m["dev"] or 0) if m["devl"] else None
    if pre is None and post is None and dev is not None:
        pre_key = (-1, 0)  # X.devN sorts before X.aN
    elif pre is None:
        pre_key = (_INF, 0)
    else:
        pre_key = pre
    return (int(m["epoch"] or 0), tuple(rel), pre_key,
            -1 if post is None else post, _INF if dev is None else dev)


def _cmp(a, b):
    ra, rb = list(a[1]), list(b[1])
    n = max(len(ra), len(rb))
    ra += [0] * (n - len(ra))
    rb += [0] * (n - len(rb))
    ka = (a[0], ra) + a[2:]
    kb = (b[0], rb) + b[2:]
    return (ka > kb) - (ka < kb)


_OPS = {"<": lambda c: c < 0, "<=": lambda c: c <= 0, ">": lambda c: c > 0,
        ">=": lambda c: c >= 0, "==": lambda c: c == 0, "!=": lambda c: c != 0}


def parse_range(text):
    """Parse '<= X', '< X', '>= A, < B' (comma = AND) into clauses."""
    if not isinstance(text, str) or not text.strip() or len(text) > MAX_FIELD:
        raise AdvisoryError("invalid version range")
    clauses = []
    for part in text.split(","):
        m = _CLAUSE_RE.fullmatch(part)
        if not m:
            raise AdvisoryError("invalid version range")
        clauses.append((m.group(1), parse_version(m.group(2))))
    return clauses


def in_range(version, range_text):
    """True if ``version`` satisfies every clause of ``range_text``."""
    v = parse_version(version)
    return all(_OPS[op](_cmp(v, bound)) for op, bound in parse_range(range_text))


def normalize_package(name):
    return re.sub(r"[-_.]+", "-", str(name)).lower()


def parse_package_spec(spec):
    """'NAME=VERSION' -> (normalized name, version string)."""
    name, sep, ver = spec.partition("=")
    if not sep or not name.strip() or not ver.strip():
        raise AdvisoryError("--package must look like NAME=VERSION")
    parse_version(ver)
    return normalize_package(name.strip()), ver.strip()


def _field(adv, key, required=True):
    v = adv.get(key)
    if v is None and not required:
        return None
    if not isinstance(v, str) or not v or len(v) > MAX_FIELD:
        raise AdvisoryError(f"advisory field {key!r} must be a non-empty string")
    return v


def load_advisories(path):
    """Load and validate a local advisories JSON file (a list of objects)."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(4 * 1024 * 1024 + 1)
        if len(data) > 4 * 1024 * 1024:
            raise AdvisoryError("advisories file too large")
        doc = json.loads(data.decode("utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        if isinstance(exc, AdvisoryError):
            raise
        raise AdvisoryError("cannot read advisories file") from None
    if not isinstance(doc, list):
        raise AdvisoryError("advisories file must be a JSON list")
    out = []
    for adv in doc:
        if not isinstance(adv, dict):
            raise AdvisoryError("each advisory must be an object")
        rec = {"id": _field(adv, "id"), "package": _field(adv, "package"),
               "affected": _field(adv, "affected"),
               "fixed": _field(adv, "fixed", False),
               "cwe": _field(adv, "cwe", False)}
        parse_range(rec["affected"])
        if rec["fixed"]:
            parse_version(rec["fixed"])
        out.append(rec)
    return out


def classify(version, affected, fixed=None):
    """'affected', 'patched' (>= fixed) or 'not_affected'."""
    if in_range(version, affected):
        return "affected"
    if fixed and _cmp(parse_version(version), parse_version(fixed)) >= 0:
        return "patched"
    return "not_affected"


def match_advisories(advisories, packages):
    """Return deterministic records for each advisory whose package is one of
    ``packages`` (list of (normalized name, version)). Pure: no side effects."""
    out = []
    for adv in advisories:
        pkg = normalize_package(adv["package"])
        for name, ver in packages:
            if name != pkg:
                continue
            out.append({
                "advisory_id": adv["id"], "package": name, "version": ver,
                "affected_range": adv["affected"], "fixed": adv["fixed"],
                "cwe": adv["cwe"],
                "status": classify(ver, adv["affected"], adv["fixed"]),
                "source": "advisory",
            })
    out.sort(key=lambda r: (r["advisory_id"], r["package"], r["version"]))
    return out
