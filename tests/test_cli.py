import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

from security_reviewer import cli  # noqa: E402

# Synthetic fixtures are built at runtime so this source stays clean.
AWS = "AK" + "IA" + "ABCDEFGHIJKLMNOP"
GHP = "gh" + "p_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
SLACK = "xo" + "xb-" + "1234567890-abcdefghij"
PEM = "-----BEGIN RSA " + "PRIVATE" + " KEY-----"
PW = "hunter2" + "Zq9xLm"
FIXTURES = {
    "aws.txt": ('key = "' + AWS + '"\n', AWS),
    "gh.txt": ("t=" + GHP + "\n", GHP),
    "slack.txt": ("S=" + SLACK + "\n", SLACK),
    "key.pem": (PEM + "\nMIIEabc\n", None),
    "cfg.py": ('password = "' + PW + '"\n', PW),
}
LOOKALIKES = {
    "a.txt": 'k = "AK' + 'IAABCDEFGH"\n',
    "b.txt": 'password = "change' + 'me"\n',
    "c.txt": 'api_key = "your_api_' + 'key_here"\n',
    "d.txt": "k = akia" + "abcdefghijklmnop\n",
}


def run(*args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = cli.main(list(args))
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.tmp = t.name
        self.repo = os.path.join(self.tmp, "repo")
        os.mkdir(self.repo)

    def put(self, files):
        for rel, val in files.items():
            text = val[0] if isinstance(val, tuple) else val
            with open(os.path.join(self.repo, rel), "w") as fh:
                fh.write(text)


class TestReview(Base):
    def test_supported_inputs(self):
        self.put(FIXTURES)
        code, out, err = run("review", self.repo)
        self.assertEqual((code, err), (0, ""))
        doc = json.loads(out)
        self.assertEqual(doc["schema_version"], 1)
        self.assertEqual(doc["root"], ".")
        ids = {f["id"].split(":")[0] for f in doc["findings"]}
        self.assertEqual(len(doc["findings"]), 5, ids)
        paths = [f["locations"][0]["path"] for f in doc["findings"]]
        self.assertEqual(paths, sorted(paths))
        self.assertNotIn("skip_samples", doc["stats"])
        self.assertEqual(doc["stats"]["files_scanned"], 5)

    def test_clean(self):
        self.put({"ok.txt": "hello\n"})
        code, out, _ = run("review", self.repo, "--fail-on-findings")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["findings"], [])

    def test_lookalikes(self):
        self.put(LOOKALIKES)
        code, out, _ = run("review", self.repo, "--fail-on-findings")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["findings"], [])

    def test_fail_on_findings(self):
        self.put(FIXTURES)
        self.assertEqual(run("review", self.repo)[0], 0)
        self.assertEqual(run("review", self.repo, "--fail-on-findings")[0], 1)

    def test_validation_status(self):
        self.put(FIXTURES)
        v = json.loads(run("review", self.repo)[1])
        self.assertEqual({f["status"] for f in v["findings"]}, {"validated"})
        self.assertEqual(v["findings"][0]["validation"]["validated_at"],
                         "1970-01-01T00:00:00Z")
        n = json.loads(run("review", self.repo, "--no-validate")[1])
        self.assertEqual({f["status"] for f in n["findings"]}, {"hypothesis"})
        t = json.loads(run("review", self.repo, "--timestamp",
                           "2026-01-02T03:04:05Z")[1])
        self.assertEqual(t["findings"][0]["validation"]["validated_at"],
                         "2026-01-02T03:04:05Z")

    def test_redaction_and_output_file(self):
        self.put(FIXTURES)
        outf = os.path.join(self.tmp, "r.json")
        code, out, err = run("review", self.repo, "--output", outf)
        self.assertEqual((code, out, err), (0, "", ""))
        with open(outf) as fh:
            filed = fh.read()
        _, stdout, stderr = run("review", self.repo)
        self.assertEqual(filed, stdout)
        for secret in (AWS, GHP, SLACK, PW):
            for blob in (filed, stdout, stderr):
                self.assertNotIn(secret, blob)

    def test_determinism(self):
        self.put(FIXTURES)
        self.assertEqual(run("review", self.repo), run("review", self.repo))

    def test_limits(self):
        self.put(FIXTURES)
        doc = json.loads(run("review", self.repo, "--max-files", "1")[1])
        self.assertTrue(doc["stats"]["hit_file_cap"])
        self.assertEqual(doc["limits"]["max_files"], 1)

    def test_symlink_root(self):
        self.put(FIXTURES)
        link = os.path.join(self.tmp, "link")
        os.symlink(self.repo, link)
        code, out, _ = run("review", link)
        self.assertEqual(code, 0)
        self.assertEqual(len(json.loads(out)["findings"]), 5)


class TestFailures(Base):
    def check_usage(self, *args):
        code, out, err = run(*args)
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertNotIn("Traceback", err)
        self.assertTrue(err.strip())
        return err

    def test_missing(self):
        self.check_usage("review", os.path.join(self.tmp, "nope"))

    def test_file_not_dir(self):
        self.put({"f.txt": 'password = "' + PW + '"\n'})
        err = self.check_usage("review", os.path.join(self.repo, "f.txt"))
        self.assertNotIn(PW, err)

    def test_bad_flags(self):
        for bad in (["--max-files", "0"], ["--max-depth", "x"],
                    ["--timestamp", "yesterday"], ["--bogus"]):
            self.check_usage("review", self.repo, *bad)
        self.check_usage()
        self.check_usage("scan", self.repo)

    def test_unwritable_output(self):
        self.put(FIXTURES)
        err = self.check_usage("review", self.repo, "--output",
                               os.path.join(self.tmp, "no", "dir", "o.json"))
        self.assertNotIn(AWS, err)

    def check_unreadable(self, err):
        self.assertEqual(len(err.strip().splitlines()), 1)
        self.assertNotIn(self.tmp, err)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root")
    def test_unreadable_dir(self):
        self.put(FIXTURES)
        for mode in (0o000, 0o400):
            os.chmod(self.repo, mode)
            self.addCleanup(os.chmod, self.repo, 0o700)
            err = self.check_usage("review", self.repo)
            self.check_unreadable(err)
            self.assertIn("cannot read PATH", err)
        os.chmod(self.repo, 0o700)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root")
    def test_partially_unreadable(self):
        self.put(FIXTURES)
        sub = os.path.join(self.repo, "sub")
        os.mkdir(sub)
        with open(os.path.join(sub, "x.txt"), "w") as fh:
            fh.write("x\n")
        os.chmod(sub, 0)
        self.addCleanup(os.chmod, sub, 0o700)
        code, out, err = run("review", self.repo)
        self.assertEqual(code, 0)
        self.assertGreaterEqual(json.loads(out)["stats"]["skipped_unreadable"], 1)

    def test_bad_source_date_epoch(self):
        self.put(FIXTURES)
        old = os.environ.get("SOURCE_DATE_EPOCH")
        self.addCleanup(lambda: os.environ.pop("SOURCE_DATE_EPOCH", None)
                        if old is None else os.environ.update(
                            SOURCE_DATE_EPOCH=old))
        for bad in ("-1", "99999999999999", "abc"):
            os.environ["SOURCE_DATE_EPOCH"] = bad
            err = self.check_usage("review", self.repo)
            self.assertIn("SOURCE_DATE_EPOCH", err)
            # not needed when validation is skipped or timestamp is given
            self.assertEqual(run("review", self.repo, "--no-validate")[0], 0)
            self.assertEqual(run("review", self.repo, "--timestamp",
                                 "2026-01-02T03:04:05Z")[0], 0)
        os.environ["SOURCE_DATE_EPOCH"] = "253402300799"
        doc = json.loads(run("review", self.repo)[1])
        self.assertEqual(doc["findings"][0]["validation"]["validated_at"],
                         "9999-12-31T23:59:59Z")

    def test_broken_pipe(self):
        self.put(FIXTURES)

        class Broken:
            def write(self, _):
                raise BrokenPipeError

            def flush(self):
                pass

        err = io.StringIO()
        old = sys.stdout
        sys.stdout = Broken()
        try:
            with redirect_stderr(err):
                code = cli.main(["review", self.repo])
        finally:
            sys.stdout = old
        self.assertEqual(code, 2)
        self.assertEqual(err.getvalue(), "")


class TestSubprocess(Base):
    def sub(self, *args):
        env = dict(os.environ, PYTHONPATH=SRC)
        return subprocess.run(
            [sys.executable, "-m", "security_reviewer", *args],
            capture_output=True, text=True, env=env, cwd=self.tmp)

    def test_module_invocation(self):
        self.put(FIXTURES)
        p = self.sub("review", self.repo, "--fail-on-findings")
        self.assertEqual(p.returncode, 1)
        self.assertEqual(len(json.loads(p.stdout)["findings"]), 5)
        for s in (AWS, GHP, SLACK, PW):
            self.assertNotIn(s, p.stdout + p.stderr)
        self.assertEqual(p.stdout, self.sub("review", self.repo).stdout)

    def test_missing_path(self):
        p = self.sub("review", os.path.join(self.tmp, "nope"))
        self.assertEqual(p.returncode, 2)
        self.assertNotIn("Traceback", p.stderr)


class TestStaticOnly(unittest.TestCase):
    def test_no_network_or_execution(self):
        banned = ("socket", "urllib", "http", "ssl", "requests", "subprocess",
                  "ftplib", "smtplib", "importlib", "runpy", "ctypes",
                  "multiprocessing", "pickle", "eval(", "exec(", "os.system",
                  "__import__")
        for name in ("cli.py", "__main__.py", "secret_scanner.py"):
            with open(os.path.join(SRC, "security_reviewer", name)) as fh:
                src = fh.read()
            for tok in banned:
                if tok.endswith("("):
                    self.assertNotIn(tok, src, (name, tok))
                else:
                    for line in src.splitlines():
                        s = line.strip()
                        self.assertFalse(
                            s.startswith(("import " + tok, "from " + tok)),
                            (name, s))


if __name__ == "__main__":
    unittest.main()
