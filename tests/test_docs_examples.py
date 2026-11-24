"""Run the documented example commands and check the checked-in outputs."""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TS = "2026-01-02T03:04:05Z"
MANIFEST = "examples/benchmark/manifest.json"
BENCH = ["benchmark", MANIFEST, "--root", "examples/benchmark",
         "--deterministic"]
REVIEW = ["review", "examples/demo", "--timestamp", TS]


def cli(*args):
    env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "src"))
    env.pop("SOURCE_DATE_EPOCH", None)
    p = subprocess.run([sys.executable, "-m", "security_reviewer", *args],
                       cwd=ROOT, env=env, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def expected(name):
    with open(os.path.join(ROOT, "examples", "expected", name),
              encoding="utf-8") as fh:
        return fh.read()


class ReviewExample(unittest.TestCase):
    def test_review_matches_expected_and_is_deterministic(self):
        c1, o1, e1 = cli(*REVIEW)
        c2, o2, _ = cli(*REVIEW)
        self.assertEqual((c1, e1), (0, ""))
        self.assertEqual(c2, 0)
        self.assertEqual(o1, o2)
        self.assertEqual(o1, expected("review.json"))

    def test_key_fields(self):
        rep = json.loads(cli(*REVIEW)[1])
        by_rule = {f["id"].split(".")[1]: f for f in rep["findings"]}
        self.assertEqual(set(by_rule), {
            "path-join-absolute-check-incomplete",
            "tar-symlink-target-unchecked", "generic-credential"})
        self.assertEqual(by_rule["generic-credential"]["status"], "validated")
        self.assertEqual(
            by_rule["tar-symlink-target-unchecked"]["status"], "hypothesis")
        self.assertEqual(rep["root"], ".")
        self.assertEqual(rep["advisory_matches"], [])
        self.assertNotIn("synthetic-demo-not-a-real-password",
                         json.dumps(rep))
        self.assertNotIn(ROOT, json.dumps(rep))

    def test_output_file_form(self):
        with tempfile.TemporaryDirectory() as t:
            out = os.path.join(t, "r.json")
            self.assertEqual(cli(*REVIEW, "--output", out)[0], 0)
            with open(out, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), expected("review.json"))

    def test_fail_on_findings_exit_1(self):
        self.assertEqual(cli(*REVIEW, "--fail-on-findings")[0], 1)

    def test_advisory_example(self):
        args = [*REVIEW, "--advisories", "examples/demo/advisories.json",
                "--package", "demo-pkg=1.0"]
        code, out, _ = cli(*args)
        self.assertEqual(code, 0)
        self.assertEqual(out, expected("review-advisory.json"))
        rep, plain = json.loads(out), json.loads(expected("review.json"))
        self.assertEqual(rep["findings"], plain["findings"])
        self.assertEqual(rep["advisory_matches"][0]["status"], "affected")

    def test_ai_sample_matches_scanner_output(self):
        # Offline: the model text is one non-deterministic sample and is
        # never compared against a live model.
        sample = json.loads(expected("review-ai-qwen3-4b.json"))
        code, out, _ = cli("review", "examples/demo", "--advisories",
                           "examples/demo/advisories.json")
        self.assertEqual(code, 0)
        rep = json.loads(out)
        ai = sample.pop("ai_report")
        self.assertEqual(sample, rep)
        self.assertEqual(
            ai["label"],
            "AI-generated, non-authoritative; scanner findings are "
            "authoritative")
        self.assertEqual(ai["status"], "ok")
        self.assertEqual(ai["model"], "qwen3:4b")
        self.assertEqual(ai["not_summarised"], 0)
        ids = {f["id"] for f in rep["findings"]}
        self.assertTrue(ai["items"])
        for item in ai["items"]:
            self.assertIn(item["id"], ids)

    def test_usage_error_exit_2(self):
        self.assertEqual(cli("review", "examples/does-not-exist")[0], 2)


class BenchmarkExample(unittest.TestCase):
    def test_modes_match_expected(self):
        for mode in ("both", "source-only", "advisory-assisted"):
            with self.subTest(mode=mode):
                code, out, _ = cli(*BENCH, "--mode", mode)
                self.assertEqual(code, 0)
                self.assertEqual(out, expected("benchmark-%s.json" % mode))

    def test_default_mode_is_both_and_twice_identical(self):
        a, b = cli(*BENCH)[1], cli(*BENCH)[1]
        self.assertEqual(a, b)
        self.assertEqual(a, expected("benchmark-both.json"))

    def test_modes_separate_and_scores_equal(self):
        rep = json.loads(expected("benchmark-both.json"))
        so, aa = rep["modes"]["source-only"], rep["modes"]["advisory-assisted"]
        self.assertNotIn("advisory", so)
        self.assertIn("advisory", aa)
        self.assertEqual(so["overall"], aa["overall"])
        self.assertEqual(rep["split"], "dev")
        self.assertTrue(all(c["split"] == "dev"
                            for c in so["cases"].values()))

    def test_baseline_write_and_compare(self):
        with tempfile.TemporaryDirectory() as t:
            base = os.path.join(t, "baseline.json")
            self.assertEqual(cli(*BENCH, "--write-baseline", base)[0], 0)
            code, out, _ = cli(*BENCH, "--baseline", base)
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out)["regressions"], [])


class DocsReferences(unittest.TestCase):
    def docs(self):
        out = [os.path.join(ROOT, "README.md")]
        d = os.path.join(ROOT, "docs")
        out += [os.path.join(d, n) for n in sorted(os.listdir(d))
                if n.endswith(".md")]
        return out

    def test_links_and_paths_exist(self):
        link = re.compile(r"\]\(([^)#\s]+)(?:#[^)]*)?\)")
        path = re.compile(r"\b((?:examples|docs|tests|src)/[\w./-]+\w)")
        for doc in self.docs():
            with open(doc, encoding="utf-8") as fh:
                text = fh.read()
            for target in link.findall(text):
                if "://" in target:
                    continue
                full = os.path.normpath(
                    os.path.join(os.path.dirname(doc), target))
                self.assertTrue(os.path.exists(full), (doc, target))
            for target in path.findall(text):
                self.assertTrue(
                    os.path.exists(os.path.join(ROOT, target)), (doc, target))

    def test_every_expected_file_is_referenced(self):
        text = ""
        for doc in self.docs():
            with open(doc, encoding="utf-8") as fh:
                text += fh.read()
        for n in os.listdir(os.path.join(ROOT, "examples", "expected")):
            self.assertIn("expected/" + n, text, n)

    def test_documented_facts(self):
        def read(n):
            with open(os.path.join(ROOT, n), encoding="utf-8") as fh:
                return fh.read()
        lr = read("docs/local-report.md")
        for s in ("OLLAMA_NO_CLOUD=1", "0.40.16", "Q4_K_M", "qwen3:4b",
                  "359d7dd4bcdab3d86b87d73ac27966f4dbb9f5efdfcc75d34a8764a09474fae7"):
            self.assertIn(s, lr)
        bm = read("docs/benchmark.md")
        self.assertIn("outside this repository", bm)
        self.assertIn("never blended", bm)
        for rule in ("aws-access-key-id", "private-key", "github-token",
                     "slack-token", "generic-credential"):
            self.assertIn(rule, read("README.md"))
            self.assertIn(rule, read("docs/scanner.md"))


if __name__ == "__main__":
    unittest.main()
