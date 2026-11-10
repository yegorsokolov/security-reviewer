import io
import json
import os
import re
import sys
import tempfile
import textwrap
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")
sys.path.insert(0, SRC)

from security_reviewer import cli, review, vuln_detectors  # noqa: E402
from security_reviewer.advisories import (  # noqa: E402
    AdvisoryError, in_range, parse_version,
)
from security_reviewer.finding import Finding  # noqa: E402
from security_reviewer.vuln_detectors import VulnScanner  # noqa: E402

JOIN = "path-join-absolute-check-incomplete"
TAR = "tar-symlink-target-unchecked"

# Synthetic, written-from-scratch excerpts shaped like the advisories.
JOIN_VULN = '''
import os
import posixpath

def join_under(base, *names):
    """Join untrusted names under base."""
    parts = [base]
    for name in names:
        if name != "":
            name = posixpath.normpath(name)
        if (
            any(sep in name for sep in ALT)
            or os.path.isabs(name)
            or name == ".."
            or name.startswith("../")
        ):
            return None
        parts.append(name)
    return posixpath.join(*parts)
'''
_DOTS = 'or name == ".."'
JOIN_FIXED = JOIN_VULN.replace(
    _DOTS, 'or name.startswith("/")\n            ' + _DOTS)
JOIN_FIXED_TUPLE = JOIN_VULN.replace(
    _DOTS, 'or name.startswith(("/", "\\\\"))\n            ' + _DOTS)
JOIN_LOOKALIKES = {
    # isabs but no traversal test
    "a.py": "import os\ndef f(b, x):\n    if os.path.isabs(x):\n"
            "        return None\n    return os.path.join(b, x)\n",
    # '..' only appears as a join argument, not as a check
    "b.py": "import os\ndef f(d):\n    if not os.path.isabs(d):\n"
            "        d = os.path.join(os.getcwd(), d)\n"
            "    return os.path.abspath(os.path.join(d, '..'))\n",
    # no join at all
    "c.py": "import os\ndef ok(x):\n    return not os.path.isabs(x) "
            "and not x.startswith('../')\n",
    # explicit containment check instead
    "d.py": "import os\ndef f(b, x):\n    if os.path.isabs(x) or x == '..':\n"
            "        return None\n    p = os.path.join(b, x)\n"
            "    if os.path.commonpath([b, p]) != b:\n        return None\n"
            "    return p\n",
}
TAR_VULN = '''
import os

def unpack(archive, dest):
    for member in archive.getmembers():
        target = os.path.join(dest, member.name)
        if member.isdir():
            os.makedirs(target, exist_ok=True)
        elif member.issym():
            try:
                archive._extract_member(member, target)
            except Exception:
                continue
        else:
            archive.extractfile(member)
'''
TAR_FIXED_HELPER = '''
import os

def target_inside(archive, info):
    name = os.path.normpath(os.path.join(os.path.dirname(info.name),
                                         info.linkname))
    try:
        archive.getmember(name)
        return True
    except KeyError:
        return False

def unpack(archive, dest):
    for member in archive.getmembers():
        target = os.path.join(dest, member.name)
        if member.isdir():
            os.makedirs(target, exist_ok=True)
        elif member.issym():
            if not target_inside(archive, member):
                raise ValueError("escapes")
            archive._extract_member(member, target)
'''
TAR_FIXED_INLINE = '''
import os

def unpack(archive, dest):
    for member in archive.getmembers():
        if member.islnk() or member.issym():
            link = os.path.join(dest, member.linkname)
            if not link.startswith(dest):
                continue
            archive.extract(member, dest)
'''
TAR_FIXED_FILTER = '''
def unpack(archive, dest):
    for member in archive:
        if member.issym():
            archive.extract(member, dest, filter="data")
'''
TAR_LOOKALIKES = {
    "a.py": "def kinds(archive):\n    out = []\n    for m in archive:\n"
            "        if m.issym():\n            out.append('sym')\n"
            "    return out\n",
    "b.py": "def fix(archive):\n    for m in archive:\n"
            "        if m.islnk():\n            m.linkname = m.linkname.strip()\n"
            "        archive.extractfile(m)\n",
    # extraction of regular files only
    "c.py": "def f(archive, d):\n    for m in archive:\n"
            "        if m.isfile():\n            archive.extract(m, d)\n",
}
# A guarded hard-link branch must not excuse an unguarded symlink branch.
TAR_SIBLING = '''
def unpack(archive, d):
    for m in archive:
        if m.islnk():
            if m.linkname.startswith("/"):
                raise ValueError("bad")
            archive.extract(m, d)
        elif m.issym():
            archive.extract(m, d)
'''


def scan_one(text, name="mod.py"):
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, name), "w") as fh:
            fh.write(text)
        sc = VulnScanner()
        return list(sc.scan(d)), sc


def rules(text):
    return [(f.id.split(".")[1], f.locations[0].start_line)
            for f in scan_one(text)[0]]


class TestPathJoin(unittest.TestCase):
    def test_vulnerable(self):
        found = rules(JOIN_VULN)
        line = 1 + JOIN_VULN.split("\n").index(
            "            or os.path.isabs(name)")
        self.assertEqual(found, [(JOIN, line)])

    def test_patched(self):
        self.assertEqual(rules(JOIN_FIXED), [])
        self.assertEqual(rules(JOIN_FIXED_TUPLE), [])

    def test_lookalikes(self):
        for name, text in JOIN_LOOKALIKES.items():
            self.assertEqual(rules(text), [], name)

    def test_renamed_identifiers_still_match(self):
        text = (JOIN_VULN.replace("join_under", "zz").replace("name", "q")
                .replace("parts", "acc").replace("base", "root"))
        self.assertEqual([r for r, _ in rules(text)], [JOIN])


class TestTarSymlink(unittest.TestCase):
    def test_vulnerable_reports_branch_line(self):
        line = 1 + TAR_VULN.split("\n").index("        elif member.issym():")
        self.assertEqual(rules(TAR_VULN), [(TAR, line)])

    def test_patched_variants(self):
        for text in (TAR_FIXED_HELPER, TAR_FIXED_INLINE, TAR_FIXED_FILTER):
            self.assertEqual(rules(text), [])

    def test_bare_classification_and_lookalikes(self):
        for name, text in TAR_LOOKALIKES.items():
            self.assertEqual(rules(text), [], name)

    def test_sibling_guard_does_not_excuse(self):
        self.assertEqual([r for r, _ in rules(TAR_SIBLING)], [TAR])

    def test_renamed_identifiers_still_match(self):
        text = re.sub(r"\bmember\b", "e", TAR_VULN).replace("archive", "tf")
        self.assertEqual([r for r, _ in rules(text)], [TAR])


class TestHostileInputs(unittest.TestCase):
    def timed(self, text, bound=20):
        t0 = time.perf_counter()
        fs, sc = scan_one(text)
        self.assertLess(time.perf_counter() - t0, bound)
        self.assertLess(len(text), 1024 * 1024)
        return fs, sc

    def test_many_isabs_lines_scan_in_linear_time(self):
        head = ("import os\ndef f(a):\n if a == '..':\n  pass\n"
                " os.path.join(a)\n")
        fs, sc = self.timed(head + " isabs(a)\n" * 80000)
        self.assertTrue(fs)  # still detected
        self.assertEqual(sc.coverage["detector_skipped"], 0)
        fs, _ = self.timed(head + " if a.startswith('/'): pass\n"
                           + " isabs(a)\n" * 80000)
        self.assertEqual(fs, [])

    def test_many_tar_branches_scan_in_linear_time(self):
        body = "  if m.issym(): x.extract(m)\n" * 8000
        fs, _ = self.timed("def f(a):\n for m in a:\n" + body)
        self.assertTrue(fs)
        fs, _ = self.timed("def f(a):\n for m in a:\n"
                           "  if m.linkname.startswith('x'): raise E\n" + body)
        self.assertEqual(fs, [])

    def test_work_cap_skips_and_counts(self):
        with mock.patch.object(vuln_detectors, "MAX_FUNCTION_WORK", 50):
            fs, sc = scan_one(JOIN_VULN + TAR_VULN)
        self.assertEqual(fs, [])
        self.assertGreaterEqual(sc.coverage["detector_skipped"], 2)

    def test_review_coverage_reports_detector_counters(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "a.py"), "w") as fh:
                fh.write("x = 1\n")
            cov = review.scan_tree(d).coverage
        self.assertEqual((cov["detector_errors"], cov["detector_skipped"]),
                         (0, 0))
        self.assertFalse(any(cov["source_scan_caps_hit"].values()))


class TestGuardHeuristics(unittest.TestCase):
    def test_linkname_truthiness_in_branch_test_still_reports(self):
        for test, body in (
                ("m.issym() and m.linkname", "tf.extract(m, d)"),
                ("m.issym()", "t = m.linkname\n   if t:\n    tf.extract(m, d)"),
                ("m.linkname and tf.getmembers()", None)):
            if body is None:
                text = ("def f(tf, d):\n for m in tf:\n"
                        "  if m.issym():\n"
                        "   if m.linkname and tf.getmembers():\n"
                        "    continue\n   tf.extract(m, d)\n")
            else:
                text = ("def f(tf, d):\n for m in tf:\n"
                        f"  if {test}:\n   {body}\n")
            self.assertEqual([r for r, _ in rules(text)], [TAR], text)
        text = ("def f(tf, d):\n for m in tf:\n"
                "  if m.issym() and m.linkname:\n   tf.extract(m, d)\n")
        self.assertEqual([r for r, _ in rules(text)], [TAR])
        text = ("def f(tf, d):\n for m in tf:\n  t = m.linkname\n"
                "  if m.issym() and t:\n   tf.extract(m, d)\n")
        self.assertEqual([r for r, _ in rules(text)], [TAR])

    def test_strong_branch_test_still_skips(self):
        text = ("def f(tf, d):\n for m in tf:\n"
                "  if m.issym() and m.linkname.startswith('/'):\n"
                "   raise E\n  elif m.issym():\n   pass\n")
        self.assertEqual(rules(text), [])

    def test_truthiness_check_is_not_a_tar_guard(self):
        text = ("def f(a, d):\n for m in a:\n  if m.issym():\n"
                "   if not m.linkname:\n    continue\n   a.extract(m, d)\n")
        self.assertEqual([r for r, _ in rules(text)], [TAR])

    def test_resolution_guards_are_accepted(self):
        for check in ("not os.path.realpath(m.linkname).startswith(d)",
                      "m.linkname not in a.getnames()",
                      "not os.path.commonpath([d, m.linkname]) == d"):
            text = ("def f(a, d):\n for m in a:\n  if m.issym():\n"
                    f"   if {check}:\n    raise ValueError\n"
                    "   a.extract(m, d)\n")
            self.assertEqual(rules(text), [], check)

    def test_split_slash_counts_as_slash_check_documented_limitation(self):
        text = JOIN_VULN.replace(
            _DOTS, 'or name.split("/")[0] == ""\n            ' + _DOTS)
        self.assertEqual(rules(text), [])  # known false negative (docs)


class TestFindingShape(unittest.TestCase):
    def test_schema_and_snippet(self):
        (f,), _ = scan_one(JOIN_VULN)
        again = Finding.from_dict(f.to_dict())
        self.assertEqual(again, f)
        d = f.to_dict()
        self.assertEqual((d["origin"], d["cwe"], d["status"]),
                         ("static_tool", "CWE-22", "hypothesis"))
        self.assertTrue(d["remediation"]["summary"])
        snip = [e["snippet"] for e in d["evidence"] if "snippet" in e]
        self.assertEqual(snip, ["or os.path.isabs(name)"])
        self.assertTrue(f.id.startswith("vuln." + JOIN + "."))

    def test_secret_like_line_is_not_echoed(self):
        key = "AK" + "IA" + "ABCDEFGHIJKLMNOP"
        text = JOIN_VULN.replace(
            "or os.path.isabs(name)",
            "or os.path.isabs(name)  # " + key)
        (f,), _ = scan_one(text)
        self.assertNotIn(key, f.to_json())
        self.assertNotIn("snippet", f.to_json())

    def test_deterministic(self):
        a = [f.to_json() for f in scan_one(JOIN_VULN + TAR_VULN)[0]]
        b = [f.to_json() for f in scan_one(JOIN_VULN + TAR_VULN)[0]]
        self.assertEqual(a, b)


class TestCoverage(unittest.TestCase):
    def test_counts(self):
        with tempfile.TemporaryDirectory() as d:
            for n, t in (("ok.py", "x = 1\n"), ("bad.py", "def (:\n"),
                         ("a.js", "var x;\n"), ("README", "hi\n"),
                         ("v.py", JOIN_VULN)):
                with open(os.path.join(d, n), "w") as fh:
                    fh.write(t)
            sc = VulnScanner()
            fs = list(sc.scan(d))
        cov = sc.coverage
        self.assertEqual(len(fs), 1)
        self.assertEqual(cov["files_seen"],
                         {"python": 3, "javascript": 1, "other": 1})
        self.assertEqual(cov["files_parsed"], 2)
        self.assertEqual(cov["unsupported"],
                         {"unparseable": 1, "unsupported_language": 2})
        self.assertEqual(cov["rules_run"], sorted([JOIN, TAR]))

    def test_deep_nesting_is_unsupported_not_fatal(self):
        text = "x = " + "(" * 5000 + "1" + ")" * 5000 + "\n"
        fs, sc = scan_one(text)
        self.assertEqual(fs, [])
        self.assertEqual(sc.coverage["unsupported"]["unparseable"], 1)

    def test_scanned_code_is_never_executed(self):
        with tempfile.TemporaryDirectory() as d:
            marker = os.path.join(d, "ran")
            with open(os.path.join(d, "evil.py"), "w") as fh:
                fh.write(f"open({marker!r}, 'w').close()\n")
            list(VulnScanner().scan(d))
            self.assertFalse(os.path.exists(marker))


def run(*args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = cli.main(list(args))
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


class CliBase(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.tmp = t.name
        self.repo = os.path.join(self.tmp, "repo")
        os.mkdir(self.repo)

    def put(self, name, text):
        with open(os.path.join(self.repo, name), "w") as fh:
            fh.write(text)


class TestCli(CliBase):
    def setUp(self):
        super().setUp()
        self.put("sec.py", textwrap.dedent('''\
            password = "hunter2''' + '''Zq9xLm"
            '''))
        self.put("join.py", JOIN_VULN)
        self.put("tar.py", TAR_VULN)

    def kinds(self, doc):
        return sorted({f["id"].split(".")[0] + ":" + f["id"].split(".")[1]
                       for f in doc["findings"]})

    def test_default_runs_both(self):
        code, out, _ = run("review", self.repo)
        doc = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(self.kinds(doc), [
            "secret:generic-credential", "vuln:" + JOIN, "vuln:" + TAR])
        cov = doc["coverage"]
        self.assertEqual(cov["rules_run"]["vulnerability"],
                         sorted([JOIN, TAR]))
        self.assertIn("generic-credential", cov["rules_run"]["secret"])
        self.assertEqual(cov["files_seen"], {"python": 3})
        self.assertEqual(cov["files_parsed"], 3)
        self.assertEqual(doc["advisory_matches"], [])
        self.assertIn("files_scanned", doc["stats"])

    def test_disable_flags(self):
        doc = json.loads(run("review", self.repo, "--no-vuln")[1])
        self.assertEqual(self.kinds(doc), ["secret:generic-credential"])
        self.assertFalse(doc["coverage"]["source_detectors_ran"])
        self.assertEqual(doc["coverage"]["rules_run"]["vulnerability"], [])
        doc = json.loads(run("review", self.repo, "--no-secrets")[1])
        self.assertEqual(self.kinds(doc), ["vuln:" + JOIN, "vuln:" + TAR])
        self.assertEqual(doc["coverage"]["rules_run"]["secret"], [])
        code, _, err = run("review", self.repo, "--no-secrets", "--no-vuln")
        self.assertEqual(code, 2)

    def test_vuln_findings_stay_hypothesis_and_work_without_ai(self):
        doc = json.loads(run("review", self.repo)[1])
        for f in doc["findings"]:
            if f["id"].startswith("vuln."):
                self.assertEqual(
                    (f["origin"], f["status"]), ("static_tool", "hypothesis"))

    def test_fail_on_findings_and_determinism(self):
        self.assertEqual(run("review", self.repo, "--fail-on-findings")[0], 1)
        self.assertEqual(run("review", self.repo), run("review", self.repo))
        self.put("sec.py", "x = 1\n")
        self.put("join.py", JOIN_FIXED)
        self.put("tar.py", TAR_FIXED_HELPER)
        self.assertEqual(run("review", self.repo, "--fail-on-findings")[0], 0)

    def test_unparseable_counted(self):
        self.put("broken.py", "def (:\n")
        doc = json.loads(run("review", self.repo)[1])
        self.assertEqual(doc["coverage"]["unsupported"]["unparseable"], 1)
        self.assertEqual(doc["coverage"]["files_parsed"], 3)


class TestAdvisories(CliBase):
    def setUp(self):
        super().setUp()
        self.put("join.py", JOIN_VULN)
        self.adv = os.path.join(self.tmp, "adv.json")
        self.write_adv([
            {"id": "ADV-1", "package": "Demo_Pkg", "affected": "<= 1.0",
             "fixed": "1.1", "cwe": "CWE-22"},
            {"id": "ADV-2", "package": "demo-pkg",
             "affected": ">= 0.8, < 0.9", "fixed": "0.9", "cwe": "CWE-22"},
            {"id": "ADV-3", "package": "other", "affected": "< 9"},
        ])

    def write_adv(self, data):
        with open(self.adv, "w") as fh:
            json.dump(data, fh)

    def review(self, *extra):
        code, out, err = run("review", self.repo, "--advisories", self.adv,
                             *extra)
        return code, json.loads(out) if out else None, err

    def status(self, version):
        _, doc, _ = self.review("--package", "demo.pkg=" + version)
        return {m["advisory_id"]: m["status"] for m in doc["advisory_matches"]}

    def test_in_range_patched_out_of_range(self):
        self.assertEqual(self.status("1.0"), {"ADV-1": "affected",
                                              "ADV-2": "patched"})
        self.assertEqual(self.status("1.1"), {"ADV-1": "patched",
                                              "ADV-2": "patched"})
        self.assertEqual(self.status("0.8.5"), {"ADV-1": "affected",
                                               "ADV-2": "affected"})
        self.assertEqual(self.status("0.5"), {"ADV-1": "affected",
                                              "ADV-2": "not_affected"})

    def test_advisories_never_alter_findings(self):
        _, plain, _ = self.review()
        base = json.loads(run("review", self.repo)[1])
        for v in ("0.5", "1.0", "1.1"):
            _, doc, _ = self.review("--package", "demo-pkg=" + v)
            self.assertEqual(doc["findings"], base["findings"])
            self.assertEqual(doc["coverage"], base["coverage"])
            self.assertEqual(doc["stats"], base["stats"])
            self.assertNotIn("ADV-1", json.dumps(doc["findings"]))
        self.assertEqual(plain["findings"], base["findings"])
        self.assertEqual(plain["advisory_matches"], [])

    def test_unrelated_package_has_no_matches(self):
        _, doc, _ = self.review("--package", "nothing=1.0")
        self.assertEqual(doc["advisory_matches"], [])

    def test_bad_inputs_are_usage_errors(self):
        self.assertEqual(run("review", self.repo, "--package", "x")[0], 2)
        code, _, err = run("review", self.repo, "--package", "x=1.0")
        self.assertEqual(code, 2)
        self.assertIn("--package requires --advisories", err)
        self.assertEqual(run("review", self.repo, "--package", "x=zz")[0], 2)
        self.assertEqual(run("review", self.repo, "--advisories",
                             os.path.join(self.tmp, "no.json"))[0], 2)
        self.write_adv([{"id": "A", "package": "p", "affected": "~= 1"}])
        self.assertEqual(self.review()[0], 2)
        self.write_adv({"id": "A"})
        self.assertEqual(self.review()[0], 2)


class TestVersions(unittest.TestCase):
    def test_ordering(self):
        ordered = ["1.0.dev1", "1.0a1", "1.0b2", "1.0rc1", "1.0", "1.0.post1",
                   "1.0.1", "1.1", "2!0.1"]
        keys = [parse_version(v) for v in ordered]
        for a, b in zip(ordered, ordered[1:]):
            self.assertTrue(in_range(a, "< " + b), (a, b))
            self.assertFalse(in_range(b, "<= " + a), (b, a))
        self.assertEqual(len(set(map(str, keys))), len(keys))

    def test_ranges(self):
        self.assertTrue(in_range("3.0.5", "<= 3.0.5"))
        self.assertFalse(in_range("3.0.6", "<= 3.0.5"))
        self.assertTrue(in_range("1.2", "<=1.2.0"))
        self.assertTrue(in_range("1.5", ">= 1.0, < 2.0"))
        self.assertFalse(in_range("2.0", ">= 1.0, < 2.0"))
        self.assertFalse(in_range("25.3", "<= 25.2"))

    def test_invalid(self):
        for bad in ("", "a.b", "1..2"):
            with self.assertRaises(AdvisoryError):
                parse_version(bad)
        with self.assertRaises(AdvisoryError):
            in_range("1.0", "1.0")
        with self.assertRaises(AdvisoryError):
            in_range("1.0", "<")


class TestRegistry(unittest.TestCase):
    def test_disabled_rule_does_not_fire(self):
        reduced = {k: v for k, v in vuln_detectors.DETECTORS.items()
                   if k != JOIN}
        with mock.patch.dict(vuln_detectors.DETECTORS, reduced, clear=True):
            self.assertEqual(rules(JOIN_VULN), [])
            self.assertEqual([r for r, _ in rules(TAR_VULN)], [TAR])


if __name__ == "__main__":
    unittest.main()
