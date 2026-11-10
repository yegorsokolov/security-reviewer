import copy
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
sys.path.insert(0, HERE)

from security_reviewer import benchmark, cli, vuln_detectors  # noqa: E402
from test_vuln_detectors import (  # noqa: E402
    JOIN, JOIN_FIXED, JOIN_LOOKALIKES, JOIN_VULN, TAR, TAR_FIXED_HELPER,
    TAR_LOOKALIKES, TAR_VULN,
)

AWS = "AK" + "IA" + "ABCDEFGHIJKLMNOP"
SECRET_FIXTURE = 'aws_key = "' + AWS + '"\n'
PLACEHOLDERS = ('password = "change' + 'me"\napi_key = "your_api_key_here"\n'
                'token = "AK' + 'IAABCDEFGH"\n')


def line_of(text, needle):
    return 1 + text.split("\n").index(needle)


def run(*args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = cli.main(list(args))
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


class BenchBase(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root = os.path.join(t.name, "bench")
        self.out = t.name
        self.manifest_path = os.path.join(t.name, "manifest.json")
        cases = []

        def snap(cid, files):
            d = os.path.join(self.root, "snaps", cid)
            os.makedirs(d)
            for name, text in files.items():
                with open(os.path.join(d, name), "w") as fh:
                    fh.write(text)
            return "snaps/" + cid

        def case(cid, role, files, expected=(), split="dev", **kw):
            c = {"id": cid, "split": split, "role": role,
                 "snapshot": snap(cid, files),
                 "expected": [{"rule": r, "path": p, "line": ln}
                              for r, p, ln in expected]}
            c.update(kw)
            cases.append(c)

        adv = {"id": "ADV-J", "affected": "<= 1.0", "fixed": "1.1",
               "cwe": "CWE-22"}
        case("join-vuln", "vulnerable", {"j.py": JOIN_VULN},
             [(JOIN, "j.py", line_of(JOIN_VULN,
                                     "            or os.path.isabs(name)"))],
             package="demo", version="1.0", advisory=adv)
        case("join-fixed", "fixed", {"j.py": JOIN_FIXED},
             package="demo", version="1.1", advisory=adv)
        case("tar-vuln", "vulnerable", {"t.py": TAR_VULN},
             [(TAR, "t.py", line_of(TAR_VULN, "        elif member.issym():"))])
        case("tar-fixed", "fixed", {"t.py": TAR_FIXED_HELPER})
        case("lookalikes", "lookalike",
             {**JOIN_LOOKALIKES, **{"t" + k: v
                                    for k, v in TAR_LOOKALIKES.items()}})
        case("control", "control", {"readme.txt": "nothing here\n",
                                    "x.py": "print('hi')\n"})
        case("secret-vuln", "vulnerable", {"cfg.py": SECRET_FIXTURE},
             [("aws-access-key-id", "cfg.py", 1)])
        case("placeholders", "lookalike", {"cfg.py": PLACEHOLDERS})
        case("held-join", "vulnerable", {"h.py": JOIN_VULN}, [
            (JOIN, "h.py", line_of(JOIN_VULN, "            or os.path.isabs(name)"))],
            split="heldout")
        self.cases = cases
        self.write_manifest()

    def write_manifest(self, cases=None):
        with open(self.manifest_path, "w") as fh:
            json.dump({"schema": 1, "cases": cases or self.cases}, fh)

    def bm(self, *extra, root=True):
        args = ["benchmark", self.manifest_path]
        if root:
            args += ["--root", self.root]
        code, out, err = run(*args, *extra)
        return code, (json.loads(out) if out else None), err


class TestScoring(BenchBase):
    def test_clean_run_dev(self):
        code, rep, err = self.bm("--deterministic")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(rep["case_count"], 8)  # held-out excluded
        self.assertNotIn("held-join", rep["modes"]["source-only"]["cases"])
        for mode in ("source-only", "advisory-assisted"):
            o = rep["modes"][mode]["overall"]
            self.assertEqual((o["tp"], o["fp"], o["fn"]), (3, 0, 0), mode)
            self.assertEqual((o["precision"], o["recall"]), (1.0, 1.0))
            self.assertEqual(rep["modes"][mode]["false_alarms_by_role"],
                             {"fixed": 0, "lookalike": 0, "control": 0})
        self.assertEqual(rep["failed_expectations"], [])

    def test_modes_are_separate_sections(self):
        _, rep, _ = self.bm("--deterministic")
        so, aa = rep["modes"]["source-only"], rep["modes"]["advisory-assisted"]
        self.assertNotIn("advisory", so)
        self.assertNotIn("advisory", so["cases"]["join-vuln"])
        a = aa["cases"]["join-vuln"]["advisory"]
        self.assertEqual((a["status"], a["in_range"]), ("affected", True))
        self.assertEqual(aa["cases"]["join-fixed"]["advisory"]["status"],
                         "patched")
        self.assertEqual(aa["advisory"]["corroborated_tp"], 1)
        self.assertEqual(aa["advisory"]["in_range_cases"], 1)
        self.assertEqual(aa["cases"]["join-vuln"]["corroborated_findings"], 1)
        # advisory info never changes source scores
        for cid, c in so["cases"].items():
            for k in ("tp", "fp", "fn", "found"):
                self.assertEqual(c[k], aa["cases"][cid][k])

    def test_single_mode_and_splits(self):
        _, rep, _ = self.bm("--mode", "source-only", "--deterministic")
        self.assertEqual(list(rep["modes"]), ["source-only"])
        _, rep, _ = self.bm("--split", "heldout", "--deterministic")
        self.assertEqual(list(rep["modes"]["source-only"]["cases"]),
                         ["held-join"])
        _, rep, _ = self.bm("--split", "all", "--deterministic")
        self.assertEqual(rep["case_count"], 9)

    def test_line_tolerance(self):
        for delta, ok in ((2, True), (-2, True), (3, False)):
            cases = copy.deepcopy(self.cases)
            cases[0]["expected"][0]["line"] += delta
            self.write_manifest(cases)
            o = self.bm("--deterministic")[1]["modes"]["source-only"]
            self.assertEqual(o["cases"]["join-vuln"]["tp"], int(ok), delta)

    def test_false_alarm_on_fixed_case_fails(self):
        cases = copy.deepcopy(self.cases)
        cases[1]["snapshot"] = cases[0]["snapshot"]  # "fixed" is vulnerable
        self.write_manifest(cases)
        code, rep, err = self.bm("--deterministic")
        self.assertEqual(code, 1)
        self.assertEqual(
            rep["modes"]["source-only"]["false_alarms_by_role"]["fixed"], 1)
        self.assertIn("join-fixed", err)

    def test_labels_are_not_given_to_the_scanner(self):
        seen = []
        real = benchmark.scan_tree

        def spy(*a, **k):
            seen.append((a, k))
            return real(*a, **k)

        with mock.patch.object(benchmark, "scan_tree", spy):
            self.bm("--deterministic")
        self.assertEqual(len(seen), 8)
        for a, k in seen:
            self.assertEqual((len(a), k), (1, {}))
            self.assertTrue(a[0].startswith(self.root))

    def test_determinism_and_runtime(self):
        a = self.bm("--deterministic")
        self.assertEqual(a, self.bm("--deterministic"))
        self.assertNotIn("runtime_ms", json.dumps(a[1]))
        _, rep, _ = self.bm()
        self.assertIn("runtime_ms", rep["modes"]["source-only"]["cases"]
                      ["join-vuln"])

    def test_synthetic_credentials_and_placeholders(self):
        _, rep, _ = self.bm("--deterministic")
        cs = rep["modes"]["source-only"]["cases"]
        self.assertEqual(cs["secret-vuln"]["tp"], 1)
        self.assertEqual(cs["placeholders"]["findings"], 0)
        self.assertNotIn(AWS, json.dumps(rep))

    def test_usage_errors(self):
        self.assertEqual(self.bm(root=False)[0], 2)
        with open(self.manifest_path, "w") as fh:
            fh.write("{")
        self.assertEqual(self.bm()[0], 2)
        bad = copy.deepcopy(self.cases)
        bad[0]["snapshot"] = "../x"
        self.write_manifest(bad)
        self.assertEqual(self.bm()[0], 2)
        bad = copy.deepcopy(self.cases)
        bad[1]["expected"] = [{"rule": "r", "path": "p", "line": 1}]
        self.write_manifest(bad)
        self.assertEqual(self.bm()[0], 2)
        self.write_manifest()
        self.assertEqual(self.bm("--split", "nope")[0], 2)

    def test_snapshot_symlink_rejected(self):
        os.symlink(self.out, os.path.join(self.root, "snaps", "link"))
        cases = copy.deepcopy(self.cases)
        cases[0]["snapshot"] = "snaps/link"
        self.write_manifest(cases)
        self.assertEqual(self.bm()[0], 2)


class TestRegression(BenchBase):
    def setUp(self):
        super().setUp()
        self.base = os.path.join(self.out, "baseline.json")

    def write_baseline(self):
        code, _, _ = self.bm("--deterministic", "--write-baseline", self.base)
        self.assertEqual(code, 0)
        with open(self.base, "rb") as fh:
            return fh.read()

    def read(self, path):
        with open(path, "rb") as fh:
            return fh.read()

    def test_baseline_has_no_runtime_and_clean_compare_passes(self):
        text = self.write_baseline()
        self.assertNotIn(b"runtime", text)
        code, rep, err = self.bm("--baseline", self.base)  # with runtimes
        self.assertEqual((code, err, rep["regressions"]), (0, "", []))

    def test_degraded_scanner_is_rejected_expectations_untouched(self):
        baseline = self.write_baseline()
        manifest = self.read(self.manifest_path)
        reduced = {k: v for k, v in vuln_detectors.DETECTORS.items()
                   if k != TAR}
        with mock.patch.dict(vuln_detectors.DETECTORS, reduced, clear=True):
            code, rep, err = self.bm("--baseline", self.base,
                                     "--deterministic")
        self.assertEqual(code, 1)
        joined = "\n".join(rep["regressions"])
        self.assertIn("recall regressed", joined)
        self.assertIn("case tar-vuln: TP 1 -> 0", joined)
        self.assertIn("tar-vuln", err)
        # expectations and baseline are not weakened or rewritten
        self.assertEqual(self.read(self.manifest_path), manifest)
        self.assertEqual(self.read(self.base), baseline)
        self.assertEqual(rep["modes"]["source-only"]["cases"]["tar-vuln"]
                         ["expected"][0][0], TAR)

    def test_new_false_positive_on_fixed_case_is_rejected(self):
        self.write_baseline()
        # make a fixed case vulnerable-looking: false positive appears
        cases = copy.deepcopy(self.cases)
        with open(os.path.join(self.root, cases[1]["snapshot"], "j.py"),
                  "w") as fh:
            fh.write(JOIN_VULN)
        code, rep, _ = self.bm("--baseline", self.base, "--deterministic")
        self.assertEqual(code, 1)
        joined = "\n".join(rep["regressions"])
        self.assertIn("case join-fixed: false positives 0 -> 1", joined)
        self.assertIn("precision regressed", joined)

    def test_weakening_expectations_is_rejected(self):
        self.write_baseline()
        cases = copy.deepcopy(self.cases)
        cases[2]["expected"][0]["line"] += 50  # moved away from the finding
        self.write_manifest(cases)
        code, rep, _ = self.bm("--baseline", self.base, "--deterministic")
        self.assertEqual(code, 1)
        self.assertIn("expectations weakened or changed",
                      "\n".join(rep["regressions"]))
        # dropping a case is also a regression
        self.write_manifest([c for c in self.cases if c["id"] != "tar-vuln"])
        code, rep, _ = self.bm("--baseline", self.base, "--deterministic")
        self.assertEqual(code, 1)
        self.assertIn("missing from current run", "\n".join(rep["regressions"]))

    def test_improvement_is_not_a_regression_and_baseline_not_updated(self):
        # baseline recorded with a degraded scanner, then fully restored
        reduced = {k: v for k, v in vuln_detectors.DETECTORS.items()
                   if k != TAR}
        with mock.patch.dict(vuln_detectors.DETECTORS, reduced, clear=True):
            self.bm("--deterministic", "--write-baseline", self.base)
        before = self.read(self.base)
        code, rep, _ = self.bm("--baseline", self.base, "--deterministic")
        self.assertEqual((code, rep["regressions"]), (0, []))
        self.assertEqual(self.read(self.base), before)

    def test_regression_blocks_baseline_rewrite(self):
        baseline = self.write_baseline()
        reduced = {k: v for k, v in vuln_detectors.DETECTORS.items()
                   if k != JOIN}
        with mock.patch.dict(vuln_detectors.DETECTORS, reduced, clear=True):
            code, _, _ = self.bm("--baseline", self.base, "--write-baseline",
                                 self.base, "--deterministic")
        self.assertEqual(code, 1)
        self.assertEqual(self.read(self.base), baseline)

    def test_baseline_misuse_is_usage_error(self):
        self.write_baseline()
        self.assertEqual(self.bm("--baseline", self.base, "--split",
                                 "heldout")[0], 2)
        self.assertEqual(self.bm("--baseline",
                                 os.path.join(self.out, "none.json"))[0], 2)
        with open(self.base, "w") as fh:
            fh.write("[]")
        self.assertEqual(self.bm("--baseline", self.base)[0], 2)


if __name__ == "__main__":
    unittest.main()
