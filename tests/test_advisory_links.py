import json
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace as NS

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "src"))

from security_reviewer import advisories as adv  # noqa: E402
from tests.test_cli import Base, run  # noqa: E402
from tests.test_vuln_detectors import JOIN_VULN  # noqa: E402


def finding(fid, path, cwe):
    return NS(id=fid, cwe=cwe, locations=[NS(path=path)])


def match(status="affected", path=None, cwe=None):
    return {"advisory_id": "A", "status": status, "path": path, "cwe": cwe}


FS = [finding("f2", "a/b.py", "CWE-22"), finding("f1", "a/b.py", "CWE-22"),
      finding("f3", "c.py", "CWE-89")]


class TestPathValidation(unittest.TestCase):
    def load(self, **extra):
        rec = {"id": "A", "package": "p", "affected": "<2"}
        rec.update(extra)
        with tempfile.TemporaryDirectory() as d:
            fn = os.path.join(d, "a.json")
            with open(fn, "w") as fh:
                json.dump([rec], fh)
            return adv.load_advisories(fn)[0]

    def test_absent_and_valid(self):
        self.assertIsNone(self.load()["path"])
        self.assertEqual(self.load(path="src/x.py")["path"], "src/x.py")

    def test_invalid(self):
        for bad in ("", "/abs", "a\\b", "../x", "a/../b", "a/..", "a\0b",
                    "C:x", 5, "x" * 201):
            with self.assertRaises(adv.AdvisoryError, msg=repr(bad)):
                self.load(path=bad)

    def test_dotted_names_ok(self):
        self.assertEqual(self.load(path="a/..b/c..d")["path"], "a/..b/c..d")

    def test_match_includes_path(self):
        a = self.load(path="x.py")
        m = adv.match_advisories([a], [("p", "1")])
        self.assertEqual(m[0]["path"], "x.py")


class TestLink(unittest.TestCase):
    def rel(self, **kw):
        return adv.link_findings([match(**kw)], FS)[0]["related_findings"]

    def test_path_only(self):
        self.assertEqual(self.rel(path="a/b.py"), ["f1", "f2"])

    def test_cwe_only(self):
        self.assertEqual(self.rel(cwe="CWE-89"), ["f3"])

    def test_both(self):
        self.assertEqual(self.rel(path="a/b.py", cwe="CWE-22"), ["f1", "f2"])
        self.assertEqual(self.rel(path="a/b.py", cwe="CWE-89"), [])

    def test_neither(self):
        self.assertEqual(self.rel(), [])

    def test_mismatch(self):
        self.assertEqual(self.rel(path="a/b.pyc"), [])
        self.assertEqual(self.rel(path="A/b.py"), [])
        self.assertEqual(self.rel(cwe="CWE-1"), [])

    def test_status(self):
        for st in ("patched", "not_affected"):
            self.assertEqual(self.rel(status=st, path="a/b.py"), [])

    def test_findings_untouched(self):
        before = [(f.id, f.cwe, f.locations[0].path) for f in FS]
        adv.link_findings([match(path="a/b.py")], FS)
        self.assertEqual(before, [(f.id, f.cwe, f.locations[0].path)
                                  for f in FS])


class TestCli(Base):
    def advfile(self, **extra):
        rec = {"id": "ADV-1", "package": "demo", "affected": "<2.0"}
        rec.update(extra)
        fn = os.path.join(self.tmp, "adv.json")
        with open(fn, "w") as fh:
            json.dump([rec], fh)
        return fn

    def test_end_to_end(self):
        self.put({"util.py": JOIN_VULN})
        code0, base, _ = run("review", self.repo)
        base = json.loads(base)
        f = base["findings"][0]
        fn = self.advfile(path="util.py", cwe=f["cwe"])
        code, out, _ = run("review", self.repo, "--advisories", fn,
                           "--package", "demo=1.0")
        rep = json.loads(out)
        self.assertEqual(code, code0)
        self.assertEqual(rep["findings"], base["findings"])
        self.assertEqual(rep["advisory_matches"][0]["related_findings"],
                         sorted(x["id"] for x in base["findings"]
                                if x["locations"][0]["path"] == "util.py"
                                and x.get("cwe") == f["cwe"]))
        self.assertTrue(rep["advisory_matches"][0]["related_findings"])
        fn = self.advfile(path="other.py")
        rep = json.loads(run("review", self.repo, "--advisories", fn,
                             "--package", "demo=1.0")[1])
        self.assertEqual(rep["advisory_matches"][0]["related_findings"], [])
        fn = self.advfile(path="util.py")
        rep = json.loads(run("review", self.repo, "--advisories", fn,
                             "--package", "demo=2.1")[1])
        self.assertEqual(rep["advisory_matches"][0]["related_findings"], [])

    def test_no_advisories_unchanged(self):
        self.put({"util.py": JOIN_VULN})
        rep = json.loads(run("review", self.repo)[1])
        self.assertEqual(rep["advisory_matches"], [])
        fn = self.advfile()
        self.assertEqual(
            json.loads(run("review", self.repo, "--advisories", fn)[1]
                       )["advisory_matches"], [])
        self.assertNotIn("related_findings", run("review", self.repo)[1])


if __name__ == "__main__":
    unittest.main()
