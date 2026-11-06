"""Versioned finding format (schema_version "1"). Stdlib only."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum
from typing import Any

SCHEMA_VERSION = "1"

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_CWE_RE = re.compile(r"^CWE-\d+$")
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
_URL_RE = re.compile(r"^https?://[^\s/?#]+[^\s]*$")


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Status(str, Enum):
    HYPOTHESIS = "hypothesis"
    VALIDATED = "validated"
    REJECTED = "rejected"
    FIXED = "fixed"


class Origin(str, Enum):
    STATIC_TOOL = "static_tool"
    AI = "ai"
    HUMAN = "human"


class EvidenceKind(str, Enum):
    CODE_SNIPPET = "code_snippet"
    TOOL_OUTPUT = "tool_output"
    REPRODUCTION = "reproduction"
    MODEL_REASONING = "model_reasoning"


class ValidationMethod(str, Enum):
    TOOL_CONFIRMED = "tool_confirmed"
    EXPLOIT_REPRODUCED = "exploit_reproduced"
    HUMAN_REVIEW = "human_review"


ALLOWED_TRANSITIONS = {
    Status.HYPOTHESIS: frozenset({Status.VALIDATED, Status.REJECTED}),
    Status.VALIDATED: frozenset({Status.FIXED, Status.REJECTED}),
    Status.REJECTED: frozenset(),
    Status.FIXED: frozenset(),
}


class ValidationError(ValueError):
    """Raised on invalid input; .errors is a list of 'path: message'."""

    def __init__(self, errors):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


# ---------------------------------------------------------------- helpers
def _is_int(v):
    return type(v) is int


def _obj(data, path, required, optional, errs):
    if not isinstance(data, dict):
        errs.append(f"{path}: must be an object")
        return False
    ok = True
    for k in data:
        if not isinstance(k, str) or k not in required and k not in optional:
            errs.append(f"{path}.{k}: unknown key" if path != "$" else f"{k}: unknown key")
            ok = False
    for k in required:
        if k not in data:
            errs.append(_p(path, k) + ": missing required field")
            ok = False
    return ok


def _p(path, key):
    return key if path == "$" else f"{path}.{key}"


def _str(data, path, key, errs, *, maxlen=None, minlen=1, regex=None,
         nonl=False, required=True):
    if key not in data:
        return None
    v, fp = data[key], _p(path, key)
    if not isinstance(v, str):
        errs.append(f"{fp}: must be a string")
        return None
    if len(v) < minlen:
        errs.append(f"{fp}: must not be empty" if minlen == 1 else f"{fp}: too short")
        return None
    if maxlen is not None and len(v) > maxlen:
        errs.append(f"{fp}: must be at most {maxlen} characters")
        return None
    if nonl and ("\n" in v or "\r" in v):
        errs.append(f"{fp}: must not contain newlines")
        return None
    if regex is not None and not regex.match(v):
        errs.append(f"{fp}: invalid format")
        return None
    return v


def _enum(data, path, key, cls, errs):
    if key not in data:
        return None
    v = data[key]
    if isinstance(v, str):
        try:
            return cls(v)
        except ValueError:
            pass
    errs.append(f"{_p(path, key)}: must be one of {', '.join(m.value for m in cls)}")
    return None


def _posint(data, path, key, errs, minimum=1):
    if key not in data:
        return None
    v = data[key]
    if not _is_int(v):
        errs.append(f"{_p(path, key)}: must be an integer")
        return None
    if v < minimum:
        errs.append(f"{_p(path, key)}: must be >= {minimum}")
        return None
    return v


def _list(data, path, key, errs):
    if key not in data:
        return None
    if not isinstance(data[key], list):
        errs.append(f"{_p(path, key)}: must be an array")
        return None
    return data[key]


def _valid_path(p):
    return (p != "" and not p.startswith("/") and "\\" not in p
            and "\x00" not in p and ".." not in p.split("/")
            and not re.match(r"^[A-Za-z]:", p))


# ---------------------------------------------------------------- classes
@dataclass(frozen=True)
class Location:
    path: str
    start_line: int
    end_line: int | None = None
    start_column: int | None = None
    end_column: int | None = None

    def __post_init__(self):
        if self.end_line is None:
            object.__setattr__(self, "end_line", self.start_line)

    def to_dict(self):
        d = {"path": self.path, "start_line": self.start_line,
             "end_line": self.end_line}
        if self.start_column is not None:
            d["start_column"] = self.start_column
        if self.end_column is not None:
            d["end_column"] = self.end_column
        return d

    @classmethod
    def _parse(cls, data, path, errs):
        n = len(errs)
        if not _obj(data, path, ("path", "start_line"),
                    ("end_line", "start_column", "end_column"), errs):
            if not isinstance(data, dict):
                return None
        p = _str(data, path, "path", errs)
        if p is not None and not _valid_path(p):
            errs.append(f"{_p(path, 'path')}: must be a repo-relative POSIX path "
                        "(no absolute, '..', backslash or NUL)")
        sl = _posint(data, path, "start_line", errs)
        el = _posint(data, path, "end_line", errs)
        sc = _posint(data, path, "start_column", errs)
        ec = _posint(data, path, "end_column", errs)
        if sl is not None and el is not None and el < sl:
            errs.append(f"{_p(path, 'end_line')}: must be >= start_line")
        if len(errs) != n:
            return None
        return cls(p, sl, el, sc, ec)


@dataclass(frozen=True)
class Evidence:
    kind: EvidenceKind
    summary: str
    snippet: str | None = None

    def to_dict(self):
        d = {"kind": self.kind.value, "summary": self.summary}
        if self.snippet is not None:
            d["snippet"] = self.snippet
        return d

    @classmethod
    def _parse(cls, data, path, errs):
        n = len(errs)
        _obj(data, path, ("kind", "summary"), ("snippet",), errs)
        if not isinstance(data, dict):
            return None
        k = _enum(data, path, "kind", EvidenceKind, errs)
        s = _str(data, path, "summary", errs, maxlen=2000)
        sn = _str(data, path, "snippet", errs, maxlen=4000, minlen=0)
        return cls(k, s, sn) if len(errs) == n else None


@dataclass(frozen=True)
class Remediation:
    summary: str
    patch: str | None = None
    references: tuple = ()

    def to_dict(self):
        d = {"summary": self.summary, "references": list(self.references)}
        if self.patch is not None:
            d["patch"] = self.patch
        return d

    @classmethod
    def _parse(cls, data, path, errs):
        n = len(errs)
        _obj(data, path, ("summary",), ("patch", "references"), errs)
        if not isinstance(data, dict):
            return None
        s = _str(data, path, "summary", errs)
        pt = _str(data, path, "patch", errs, minlen=0)
        refs = []
        lst = _list(data, path, "references", errs)
        for i, r in enumerate(lst or []):
            rp = f"{_p(path, 'references')}[{i}]"
            if not isinstance(r, str):
                errs.append(f"{rp}: must be a string")
            elif not _URL_RE.match(r):
                errs.append(f"{rp}: must be an http(s) URL")
            else:
                refs.append(r)
        return cls(s, pt, tuple(refs)) if len(errs) == n else None


def _ts_ok(v):
    if not _TS_RE.match(v):
        return False
    try:
        datetime.strptime(v[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class Validation:
    method: ValidationMethod
    validated_by: str
    validated_at: str
    notes: str | None = None

    def to_dict(self):
        d = {"method": self.method.value, "validated_by": self.validated_by,
             "validated_at": self.validated_at}
        if self.notes is not None:
            d["notes"] = self.notes
        return d

    @classmethod
    def _parse(cls, data, path, errs):
        n = len(errs)
        _obj(data, path, ("method", "validated_by", "validated_at"),
             ("notes",), errs)
        if not isinstance(data, dict):
            return None
        m = _enum(data, path, "method", ValidationMethod, errs)
        by = _str(data, path, "validated_by", errs)
        at = _str(data, path, "validated_at", errs)
        if at is not None and not _ts_ok(at):
            errs.append(f"{_p(path, 'validated_at')}: must be an RFC3339 UTC "
                        "timestamp ending in Z")
        notes = _str(data, path, "notes", errs, minlen=0)
        return cls(m, by, at, notes) if len(errs) == n else None


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    category: str
    severity: Severity
    confidence: Confidence
    status: Status
    origin: Origin
    locations: tuple
    evidence: tuple
    remediation: Remediation
    validation: Validation | None = None
    cwe: str | None = None
    description: str | None = None
    schema_version: str = SCHEMA_VERSION

    # --- serialization
    def to_dict(self):
        d = {
            "schema_version": self.schema_version,
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "status": self.status.value,
            "origin": self.origin.value,
            "locations": [x.to_dict() for x in self.locations],
            "evidence": [x.to_dict() for x in self.evidence],
            "remediation": self.remediation.to_dict(),
        }
        if self.validation is not None:
            d["validation"] = self.validation.to_dict()
        if self.cwe is not None:
            d["cwe"] = self.cwe
        if self.description is not None:
            d["description"] = self.description
        return d

    def to_json(self):
        return json.dumps(self.to_dict(), sort_keys=True, indent=2,
                          ensure_ascii=False) + "\n"

    @classmethod
    def from_dict(cls, data):
        errs: list = []
        f = cls._parse(data, errs)
        if errs or f is None:
            raise ValidationError(errs)
        return f

    @classmethod
    def from_json(cls, text):
        try:
            data = json.loads(text)
        except (ValueError, TypeError) as e:
            raise ValidationError([f"$: invalid JSON: {e}"]) from None
        if not isinstance(data, dict):
            raise ValidationError(["$: must be a JSON object"])
        return cls.from_dict(data)

    @classmethod
    def _parse(cls, data, errs):
        req = ("schema_version", "id", "title", "category", "severity",
               "confidence", "status", "origin", "locations", "evidence",
               "remediation", "validation")
        _obj(data, "$", tuple(k for k in req if k != "validation"),
             ("cwe", "description", "validation"), errs)
        if not isinstance(data, dict):
            return None
        if "schema_version" in data and data["schema_version"] != SCHEMA_VERSION:
            errs.append(f'schema_version: must be the string "{SCHEMA_VERSION}"')
        fid = _str(data, "$", "id", errs, regex=_ID_RE)
        title = _str(data, "$", "title", errs, maxlen=200, nonl=True)
        cat = _str(data, "$", "category", errs, maxlen=100)
        cwe = _str(data, "$", "cwe", errs, regex=_CWE_RE)
        desc = _str(data, "$", "description", errs, maxlen=5000, minlen=0)
        sev = _enum(data, "$", "severity", Severity, errs)
        conf = _enum(data, "$", "confidence", Confidence, errs)
        st = _enum(data, "$", "status", Status, errs)
        org = _enum(data, "$", "origin", Origin, errs)

        locs = []
        lst = _list(data, "$", "locations", errs)
        if lst is not None and not lst:
            errs.append("locations: must contain at least one location")
        for i, x in enumerate(lst or []):
            r = Location._parse(x, f"locations[{i}]", errs)
            if r:
                locs.append(r)
        evs = []
        for i, x in enumerate(_list(data, "$", "evidence", errs) or []):
            r = Evidence._parse(x, f"evidence[{i}]", errs)
            if r:
                evs.append(r)
        rem = None
        if "remediation" in data:
            rem = Remediation._parse(data["remediation"], "remediation", errs)
        val = None
        val_ok = True
        if data.get("validation") is not None:
            val = Validation._parse(data["validation"], "validation", errs)
            val_ok = val is not None
        elif "validation" in data and data["validation"] is not None:
            val_ok = False

        # cross-field rules (only when the involved fields parsed)
        if st is not None and val_ok:
            has_val = val is not None
            real_ev = any(e.kind != EvidenceKind.MODEL_REASONING for e in evs)
            if st is Status.VALIDATED:
                if not has_val:
                    errs.append("validation: required when status is validated")
                if not real_ev:
                    errs.append("evidence: validated requires at least one "
                                "evidence not of kind model_reasoning")
            elif st is Status.REJECTED:
                if not has_val or not val.notes:
                    errs.append("validation.notes: rejected requires validation "
                                "with notes")
            elif st is Status.HYPOTHESIS:
                if has_val:
                    errs.append("validation: must be null when status is hypothesis")
                if conf is Confidence.HIGH:
                    errs.append("confidence: must not be high when status is "
                                "hypothesis")
                if sev is Severity.CRITICAL and not evs:
                    errs.append("evidence: critical hypothesis requires at "
                                "least one evidence")
        if errs:
            return None
        return cls(fid, title, cat, sev, conf, st, org, tuple(locs), tuple(evs),
                   rem, val, cwe, desc)

    # --- lifecycle
    def transition(self, new_status, validation=None):
        try:
            new_status = Status(new_status)
        except ValueError:
            raise ValidationError(
                [f"status: unknown status {new_status!r}"]) from None
        if new_status not in ALLOWED_TRANSITIONS[self.status]:
            raise ValidationError(
                [f"status: illegal transition {self.status.value} -> "
                 f"{new_status.value}"])
        cand = replace(self, status=new_status,
                       validation=validation if validation is not None
                       else self.validation)
        return Finding.from_dict(cand.to_dict())
