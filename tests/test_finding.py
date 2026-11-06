import copy
import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from security_reviewer.finding import (  # noqa: E402
    ALLOWED_TRANSITIONS, Finding, Status, Validation, ValidationError,
    ValidationMethod,
)

DOC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs", "finding-format.md")


def base():
    return {
        "schema_version": "1", "id": "F-1", "title": "T", "category": "xss",
        "severity": "high", "confidence": "medium", "status": "hypothesis",
        "origin": "ai",
        "locations": [{"path": "a/b.py", "start_line": 3}],
        "evidence": [{"kind": "model_reasoning", "summary": "s"}],
        "remediation": {"summary": "fix"},
    }


def validated():
    d = base()
    d.update(status="validated", confidence="high",
             evidence=[{"kind": "tool_output", "summary": "s"}],
             validation={"method": "tool_confirmed", "validated_by": "me",
                         "validated_at": "2026-01-02T03:04:05Z"})
    return d


def VAL(notes=None):
    return Validation(ValidationMethod.HUMAN_REVIEW, "me", "2026-01-02T03:04:05Z", notes)


class T(unittest.TestCase):
    def bad(self, d, frag):
        with self.assertRaises(ValidationError) as c:
            Finding.from_dict(d)
        self.assertTrue(any(frag in e for e in c.exception.errors), c.exception.errors)
        return c.exception.errors

    def mod(self, f=base, **kw):
        d = f()
        d.update(kw)
        return d

    def test_ok_and_defaults(self):
        f = Finding.from_dict(base())
        self.assertEqual(f.locations[0].end_line, 3)
        self.assertIsInstance(ValidationError([]), ValueError)
        Finding.from_dict(validated())

    def test_missing_fields(self):
        for k in base():
            d = base()
            del d[k]
            self.bad(d, f"{k}: missing")

    def test_unknown_keys(self):
        self.bad(self.mod(x=1), "x: unknown key")
        d = base(); d["locations"][0]["z"] = 1
        self.bad(d, "locations[0].z: unknown key")
        d = base(); d["evidence"][0]["z"] = 1
        self.bad(d, "evidence[0].z")
        d = base(); d["remediation"]["z"] = 1
        self.bad(d, "remediation.z")
        d = validated(); d["validation"]["z"] = 1
        self.bad(d, "validation.z")

    def test_version(self):
        for v in ("2", 1, None, ""):
            self.bad(self.mod(schema_version=v), "schema_version")

    def test_enums(self):
        for k in ("severity", "confidence", "status", "origin"):
            self.bad(self.mod(**{k: "HIGH"}), k)
            self.bad(self.mod(**{k: 1}), k)
        d = base(); d["evidence"][0]["kind"] = "x"
        self.bad(d, "evidence[0].kind")
        d = validated(); d["validation"]["method"] = "x"
        self.bad(d, "validation.method")

    def test_locations(self):
        self.bad(self.mod(locations=[]), "at least one")
        self.bad(self.mod(locations="x"), "locations: must be an array")
        for p in ("", "/etc/x", "a/../b", "..", "a\\b", "a\x00b"):
            d = base(); d["locations"][0]["path"] = p
            self.bad(d, "locations[0].path")
        for sl in (0, -1, True, "1", 1.0):
            d = base(); d["locations"][0]["start_line"] = sl
            self.bad(d, "start_line")
        d = base(); d["locations"][0]["end_line"] = 2
        self.bad(d, "end_line: must be >= start_line")
        for k in ("start_column", "end_column"):
            d = base(); d["locations"][0][k] = 0
            self.bad(d, k)
        d = base(); d["locations"][0].update(end_line=5, start_column=1, end_column=9)
        Finding.from_dict(d)

    def test_evidence_remediation(self):
        d = base(); d["evidence"][0]["summary"] = ""
        self.bad(d, "evidence[0].summary")
        d = base(); d["evidence"][0]["summary"] = "x" * 2001
        self.bad(d, "evidence[0].summary")
        d = base(); d["evidence"][0]["snippet"] = "x" * 4001
        self.bad(d, "evidence[0].snippet")
        d = base(); d["remediation"]["summary"] = ""
        self.bad(d, "remediation.summary")
        d = base(); d["remediation"]["patch"] = 3
        self.bad(d, "remediation.patch")
        for u in ("javascript:alert(1)", "ftp://x.com", "http://", "https://a b"):
            d = base(); d["remediation"]["references"] = [u]
            self.bad(d, "references[0]")
        d = base(); d["remediation"]["references"] = [1]
        self.bad(d, "references[0]")

    def test_validated_rules(self):
        d = validated(); d["validation"] = None
        self.bad(d, "validation: required")
        d = validated(); d["evidence"] = [{"kind": "model_reasoning", "summary": "s"}]
        self.bad(d, "model_reasoning")
        d = validated(); d["evidence"] = []
        self.bad(d, "evidence:")

    def test_hypothesis_rules(self):
        self.bad(self.mod(confidence="high"), "confidence")
        d = base(); d["validation"] = validated()["validation"]
        self.bad(d, "validation: must be null")
        d = self.mod(severity="critical", evidence=[])
        self.bad(d, "critical hypothesis")
        Finding.from_dict(self.mod(severity="critical"))
        Finding.from_dict(self.mod(validation=None))

    def test_rejected_rules(self):
        d = self.mod(status="rejected")
        self.bad(d, "validation.notes")
        d["validation"] = validated()["validation"]
        self.bad(d, "validation.notes")
        d["validation"]["notes"] = "false positive"
        Finding.from_dict(d)

    def test_timestamp(self):
        for ts in ("2026-01-02T03:04:05+00:00", "2026-01-02 03:04:05Z",
                   "2026-13-02T03:04:05Z", "2026-01-02T03:04:05", 5, ""):
            d = validated(); d["validation"]["validated_at"] = ts
            self.bad(d, "validation.validated_at")
        d = validated(); d["validation"]["validated_at"] = "2026-01-02T03:04:05.123Z"
        Finding.from_dict(d)
        d = validated(); d["validation"]["validated_by"] = ""
        self.bad(d, "validated_by")

    def test_cwe_title_id(self):
        for c in ("CWE-", "cwe-1", "CWE-1a", 79):
            self.bad(self.mod(cwe=c), "cwe")
        Finding.from_dict(self.mod(cwe="CWE-79"))
        for t in ("", "a\nb", "x" * 201, 5):
            self.bad(self.mod(title=t), "title")
        for i in ("", "-a", ".a", "a b", "a/b", "x" * 65, 1):
            self.bad(self.mod(id=i), "id")
        Finding.from_dict(self.mod(id="x" * 64))
        self.bad(self.mod(description="x" * 5001), "description")

    def test_json_errors(self):
        for s in ("{", "[]", "3", "null", ""):
            with self.assertRaises(ValidationError):
                Finding.from_json(s)
        with self.assertRaises(ValidationError):
            Finding.from_dict([])

    def test_multi_error(self):
        d = self.mod(severity="x", id="", x=1, locations=[])
        with self.assertRaises(ValidationError) as c:
            Finding.from_dict(d)
        self.assertGreaterEqual(len(c.exception.errors), 4)
        for e in c.exception.errors:
            self.assertRegex(e, r"^[\w.\[\]]+: ")

    def test_transitions(self):
        h = Finding.from_dict(base())
        self.assertEqual(ALLOWED_TRANSITIONS[Status.HYPOTHESIS],
                         {Status.VALIDATED, Status.REJECTED})
        with self.assertRaises(ValidationError):
            h.transition("fixed")
        with self.assertRaises(ValidationError):
            h.transition("bogus")
        with self.assertRaises(ValidationError):
            h.transition("validated")  # no validation
        with self.assertRaises(ValidationError):
            h.transition("rejected", VAL())  # no notes
        r = h.transition("rejected", VAL("fp"))
        self.assertEqual(r.status, Status.REJECTED)
        self.assertEqual(h.status, Status.HYPOTHESIS)
        for s in ("validated", "fixed", "hypothesis"):
            with self.assertRaises(ValidationError):
                r.transition(s)
        v = Finding.from_dict(validated())
        fx = v.transition(Status.FIXED)
        with self.assertRaises(ValidationError):
            fx.transition("rejected", VAL("x"))
        with self.assertRaises(ValidationError):
            v.transition("hypothesis")
        # hypothesis with only model_reasoning evidence cannot validate
        with self.assertRaises(ValidationError):
            h.transition("validated", VAL())
        d = base(); d["evidence"].append({"kind": "tool_output", "summary": "t"})
        ok = Finding.from_dict(d).transition("validated", VAL())
        self.assertEqual(ok.status, Status.VALIDATED)

    def test_roundtrip(self):
        for d in (base(), validated()):
            f = Finding.from_dict(d)
            self.assertEqual(Finding.from_json(f.to_json()), f)
            self.assertEqual(f.to_json(), Finding.from_json(f.to_json()).to_json())
            self.assertEqual(f.to_json(), Finding.from_dict(copy.deepcopy(d)).to_json())
            self.assertEqual(f.to_json(), Finding.from_dict(dict(reversed(list(d.items())))).to_json())
            out = json.loads(f.to_json())
            self.assertNotIn(None, out.values())
            self.assertEqual(out["severity"], d["severity"])
        self.assertTrue(Finding.from_dict(base()).to_json().startswith('{\n  "category"'))

    def test_frozen(self):
        f = Finding.from_dict(base())
        with self.assertRaises(Exception):
            f.title = "x"

    def test_doc_examples(self):
        with open(DOC, encoding="utf-8") as fh:
            blocks = re.findall(r"```json\n(.*?)```", fh.read(), re.S)
        self.assertGreaterEqual(len(blocks), 2)
        statuses = set()
        for b in blocks:
            statuses.add(Finding.from_json(b).status.value)
        self.assertEqual(statuses, {"validated", "hypothesis"})


if __name__ == "__main__":
    unittest.main()
