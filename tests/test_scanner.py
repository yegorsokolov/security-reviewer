import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from security_reviewer import (  # noqa: E402
    Finding, LocalContextReader, Origin, Scanner, SecretScanner,
    SecretValidator, Status, Validator, ValidationMethod, Confidence,
)

# Secret-looking fixtures are built at runtime so this source stays clean.
AWS = "AK" + "IA" + "ABCDEFGHIJKLMNOP"
GHP = "gh" + "p_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
GHPAT = "github" + "_pat_" + "A1b2C3d4E5f6G7h8I9j0K1"
SLACK = "xo" + "xb-" + "1234567890-abcdefghij"
PEM = "-----BEGIN RSA " + "PRIVATE" + " KEY-----"
PW = "hunter2" + "Zq9xLm"
GENERIC = 'password = "' + PW + '"'

FIXTURES = {
    "aws-access-key-id": (AWS, 'key = "' + AWS + '"\n'),
    "private-key": (None, PEM + "\nMIIE\n"),
    "github-token": (GHP, "t=" + GHP + "\n"),
    "github-token-pat": (GHPAT, "t=" + GHPAT + "\n"),
    "slack-token": (SLACK, "SLACK=" + SLACK + "\n"),
    "generic-credential": (PW, "x = 1\n" + GENERIC + "\n"),
}


def write(root, rel, data):
    p = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as fh:
        fh.write(data if isinstance(data, bytes) else data.encode())
    return p


class ScannerTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.root = os.path.join(self._td.name, "repo")
        os.mkdir(self.root)
        self.outside = os.path.join(self._td.name, "outside")
        os.mkdir(self.outside)

    def scan(self, **kw):
        return list(SecretScanner(**kw).scan(self.root))

    def test_each_pattern(self):
        for name, (secret, content) in FIXTURES.items():
            with self.subTest(name):
                rule = name.removesuffix("-pat")
                write(self.root, "src/a.txt", content)
                fs = self.scan()
                self.assertEqual([f.id.split(".")[1] for f in fs], [rule])
                f = fs[0]
                self.assertIs(f.origin, Origin.STATIC_TOOL)
                self.assertIs(f.status, Status.HYPOTHESIS)
                self.assertNotEqual(f.confidence, Confidence.HIGH)
                self.assertEqual(f.cwe, "CWE-798")
                self.assertEqual(f.locations[0].path, "src/a.txt")
                self.assertEqual(f.locations[0].start_line,
                                 2 if name == "generic-credential" else 1)
                self.assertTrue(f.remediation.summary)
                text = f.to_json()
                if secret:
                    self.assertNotIn(secret, text)
                    self.assertNotIn(secret[:12], text)
                if name != "private-key":
                    self.assertIn("[REDACTED]", text)
                self.assertEqual(Finding.from_json(text), f)
                os.remove(os.path.join(self.root, "src", "a.txt"))

    def test_second_secret_on_line_redacted_everywhere(self):
        write(self.root, "a.txt", AWS + " " + SLACK + "\n")
        fs = self.scan()
        self.assertEqual(len(fs), 2)
        for f in fs:
            self.assertNotIn(AWS, f.to_json())
            self.assertNotIn(SLACK, f.to_json())

    def test_placeholders_ignored(self):
        lines = ['password = "changeme"', 'api_key = "your-api-key-here"',
                 'secret: "<your-secret-value>"', 'token = "example_token_value"',
                 'password = "${DB_PASSWORD}"', 'api_key = "xxxxxxxxxxxx"',
                 'secret = "short"']
        write(self.root, "a.py", "\n".join(lines) + "\n")
        self.assertEqual(self.scan(), [])

    def test_percent_format_placeholders_ignored(self):
        write(self.root, "a.py", 'SECRET = "%(secret)s"\n'
              'password = "%(db_password)s"\n')
        self.assertEqual(self.scan(), [])
        write(self.root, "b.py", 'password = "%(x)sRealValue99"\n')
        self.assertEqual(len(self.scan()), 1)

    def test_real_values_with_placeholder_substrings_detected(self):
        vals = ["Zx9!realSecretValue42", "P@ssword2024!", "myExampleTodoKey77",
                "yourCompanyProd#9921"]
        write(self.root, "a.py", "".join(
            f'password = "{v}"\n' for v in vals))
        fs = self.scan()
        self.assertEqual(len(fs), len(vals))
        for f in fs:
            for v in vals:
                self.assertNotIn(v, f.to_json())

    def test_more_generic_keywords(self):
        write(self.root, "a.py",
              'client_secret = "' + PW + '"\n'
              "aws_secret_access_key: '" + PW + "'\n"
              'auth_token="' + PW + '"\n'
              'SECRET_KEY = "' + PW + '"\n')
        fs = self.scan()
        self.assertEqual(len(fs), 4)
        self.assertTrue(all(PW not in f.to_json() for f in fs))

    def test_one_line_pem_in_json_no_leak(self):
        body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" + "KcwggSjAgEAAoIBAQC7"
        write(self.root, "k.json",
              '{"key": "' + PEM + "\\n" + body + '\\n-----END", "x": 1}\n')
        fs = self.scan()
        self.assertEqual(len(fs), 1)
        self.assertNotIn(body[:16], fs[0].to_json())
        self.assertNotIn(body[-16:], fs[0].to_json())

    def test_csv_secret_after_key_no_leak(self):
        sk = "wJalrXUtnFEMI" + "/K7MDENG/bPxRfiCYEXAMPLEKEY"
        write(self.root, "c.csv", "id,key,secret\n" + AWS + "," + sk + "\n")
        fs = self.scan()
        self.assertEqual(len(fs), 1)
        text = fs[0].to_json()
        self.assertNotIn("wJalr", text)
        self.assertNotIn("EXAMPLEKEY", text)
        self.assertNotIn(AWS, text)

    def test_long_run_before_match_masked(self):
        pre = "ZmFrZXRva2VuYmFzZTY0dmFsdWU"
        write(self.root, "a.txt", pre + " " + AWS + "\n")
        (f,) = self.scan()
        self.assertNotIn(pre, f.to_json())

    def test_secret_in_path_skipped(self):
        write(self.root, AWS + ".txt", AWS + "\n")
        write(self.root, GHP + "/f.txt", AWS + "\n")
        write(self.root, "ok.txt", AWS + "\n")
        sc = SecretScanner()
        fs = list(sc.scan(self.root))
        self.assertEqual([f.locations[0].path for f in fs], ["ok.txt"])
        self.assertEqual(sc.stats.skipped_secret_in_path, 2)
        for f in fs:
            self.assertNotIn(GHP, f.to_json())
        for _, path in sc.stats.skip_samples:
            self.assertTrue(path is None or AWS not in path)

    def test_secret_in_glued_path_components_skipped(self):
        write(self.root, "backup_" + GHP + ".txt", AWS + "\n")
        write(self.root, GHP + "_old.txt", AWS + "\n")
        write(self.root, "pre" + SLACK + "x/f.txt", AWS + "\n")
        write(self.root, "ok.txt", AWS + "\n")
        sc = SecretScanner()
        fs = list(sc.scan(self.root))
        self.assertEqual([f.locations[0].path for f in fs], ["ok.txt"])
        self.assertEqual(sc.stats.skipped_secret_in_path, 3)
        self.assertNotIn(GHP[:20], repr(sc.stats.skip_samples))

    def test_path_check_matches_every_content_rule(self):
        from security_reviewer.secret_scanner import _secret_in
        samples = [AWS, PEM, GHP, GHPAT, SLACK, GENERIC,
                   'secret_key="Abcdefgh12"', "secret-key=Abcdefgh12",
                   "secretkey=Abcdefgh12", 'aws_secret_access_key="Abcdefgh12"',
                   "client_secret: 'Abcdefgh12'", "auth_token=Abcdefgh12",
                   "api-key=Abcdefgh12", "private_key=Abcdefgh12",
                   "pre_" + GHP + "_post", "pre" + AWS + "x"]
        for smp in samples:
            for path in (smp + ".txt", smp + "/f.txt", "d/" + smp, smp):
                with self.subTest(path=path):
                    self.assertTrue(_secret_in(path))
        # real files/dirs with such names are skipped, not reported
        for i, smp in enumerate(samples[:9]):
            if "/" in smp:
                continue
            write(self.root, f"{i}/" + smp, AWS + "\n")
            write(self.root, smp + f"/{i}.txt", AWS + "\n")
        sc = SecretScanner()
        self.assertEqual(list(sc.scan(self.root)), [])
        self.assertGreaterEqual(sc.stats.skipped_secret_in_path, 10)

    def test_joined_path_secret_skipped(self):
        from security_reviewer.secret_scanner import _secret_in
        self.assertTrue(_secret_in("password=/Hunter2Hunter2"))
        write(self.root, "password=/Hunter2Hunter2", AWS + "\n")
        write(self.root, "ok.txt", AWS + "\n")
        sc = SecretScanner()
        fs = list(sc.scan(self.root))
        self.assertEqual([f.locations[0].path for f in fs], ["ok.txt"])
        self.assertEqual(sc.stats.skipped_secret_in_path, 1)
        self.assertNotIn("Hunter2", repr(sc.stats.skip_samples))

    def test_dollar_var_shape_is_case_sensitive(self):
        write(self.root, "a.py", 'password = "$uperS3cret"\n'
              'password = "$DB_PASSWORD"\n'
              'password = "<your-key>"\n'
              'password = "<a!b#c$dEf9>"\n'
              'password = "%APP_PASSWORD%"\n'
              'password = "%Zq9!x7Lm2p%"\n')
        fs = self.scan()
        self.assertEqual([f.locations[0].start_line for f in fs], [1, 4, 6])

    def _deep(self, n):
        rel = "/".join(["d"] * n)
        base = self.root
        def cleanup():
            for i in range(n, 0, -1):
                try:
                    os.rmdir(os.path.join(base, *(["d"] * i)))
                except OSError:
                    pass
        self.addCleanup(cleanup)
        cur = base
        for _ in range(n):
            cur = os.path.join(cur, "d")
            os.mkdir(cur)
        return rel

    def test_depth_cap_default_handles_very_deep_tree(self):
        rel = self._deep(1100)
        write(self.root, rel + "/s.txt", AWS + "\n")
        write(self.root, "top.txt", AWS + "\n")
        sc = SecretScanner()
        fs = list(sc.scan(self.root))
        self.assertEqual([f.locations[0].path for f in fs], ["top.txt"])
        self.assertTrue(sc.stats.hit_depth_cap)
        self.assertEqual(sc.stats.skipped_too_deep, 1)
        self.assertIn("too_deep", [r for r, _ in sc.stats.skip_samples])
        os.remove(os.path.join(self.root, *rel.split("/"), "s.txt"))

    def test_depth_cap_boundary(self):
        write(self.root, "a/b/c/s.txt", AWS + "\n")
        self.assertEqual(len(self.scan(max_depth=3)), 1)
        sc = SecretScanner(max_depth=2)
        self.assertEqual(list(sc.scan(self.root)), [])
        self.assertTrue(sc.stats.hit_depth_cap)

    def test_entry_cap(self):
        for i in range(10):
            write(self.root, f"d{i}/f.txt", "x\n")
        sc = SecretScanner(max_entries=5)
        list(sc.scan(self.root))
        self.assertTrue(sc.stats.hit_entry_cap)
        self.assertEqual(sc.stats.entries_visited, 5)

    def test_skip_samples_bounded_and_visible(self):
        for i in range(60):
            write(self.root, f"bad{i}\\x.txt", "x\n")
        sc = SecretScanner()
        list(sc.scan(self.root))
        self.assertEqual(sc.stats.skipped_bad_path, 60)
        self.assertEqual(len(sc.stats.skip_samples), 50)
        self.assertEqual(sc.stats.skip_samples[0][0], "bad_path")

    def test_symlinks_not_followed(self):
        write(self.outside, "s.txt", AWS)
        write(self.outside, "d/s.txt", AWS)
        os.symlink(os.path.join(self.outside, "s.txt"),
                   os.path.join(self.root, "link.txt"))
        os.symlink(os.path.join(self.outside, "d"),
                   os.path.join(self.root, "linkdir"))
        sc = SecretScanner()
        self.assertEqual(list(sc.scan(self.root)), [])
        self.assertEqual(sc.stats.skipped_symlink, 2)

    def test_skip_dirs(self):
        for d in (".git", "node_modules"):
            write(self.root, d + "/x.txt", AWS)
        self.assertEqual(self.scan(), [])

    def test_oversize_skipped(self):
        write(self.root, "big.txt", AWS + "\n" + "a" * 2000)
        sc = SecretScanner(max_file_size=1000)
        self.assertEqual(list(sc.scan(self.root)), [])
        self.assertEqual(sc.stats.skipped_oversize, 1)

    def test_binary_skipped(self):
        write(self.root, "b.bin", AWS.encode() + b"\x00\x01")
        sc = SecretScanner()
        self.assertEqual(list(sc.scan(self.root)), [])
        self.assertEqual(sc.stats.skipped_binary, 1)

    def test_invalid_utf8_replaced(self):
        write(self.root, "a.txt", b"\xff\xfe " + AWS.encode() + b"\n")
        self.assertEqual(len(self.scan()), 1)

    def test_caps(self):
        for i in range(5):
            write(self.root, f"f{i}.txt", AWS + "\n")
        sc = SecretScanner(max_files=2)
        self.assertEqual(len(list(sc.scan(self.root))), 2)
        self.assertTrue(sc.stats.hit_file_cap)
        sc = SecretScanner(max_total_bytes=len(AWS) * 2 + 4)
        self.assertEqual(len(list(sc.scan(self.root))), 2)
        self.assertTrue(sc.stats.hit_byte_cap)

    def test_findings_cap(self):
        write(self.root, "a.txt", (AWS + "\n") * 10)
        sc = SecretScanner(max_findings=3)
        self.assertEqual(len(list(sc.scan(self.root))), 3)
        self.assertTrue(sc.stats.hit_finding_cap)

    def test_line_length_cap(self):
        write(self.root, "a.txt", "a" * 300 + AWS + "\n" + AWS + "\n")
        fs = self.scan(max_line_length=100)
        self.assertEqual([f.locations[0].start_line for f in fs], [2])

    def test_bad_params(self):
        with self.assertRaises(ValueError):
            SecretScanner(max_files=0)
        with self.assertRaises(ValueError):
            list(SecretScanner().scan(os.path.join(self.root, "nope")))

    def test_weird_filename_skipped(self):
        write(self.root, "ok.txt", AWS + "\n")
        for name in ("bad\nname.txt", "back\\slash.txt", "bidi\u202ename.txt"):
            try:
                write(self.root, name, AWS + "\n")
            except OSError:
                self.skipTest("filesystem rejects name")
        try:
            write(self.root, os.fsdecode(b"inv\xffalid.txt"), AWS + "\n")
        except (OSError, UnicodeError):
            pass
        sc = SecretScanner()
        fs = list(sc.scan(self.root))
        self.assertEqual([f.locations[0].path for f in fs], ["ok.txt"])
        self.assertGreaterEqual(sc.stats.skipped_bad_path, 3)

    def test_deterministic(self):
        for p in ("z.txt", "a/b.txt", "a/a.txt", "m.txt"):
            write(self.root, p, AWS + "\n" + GENERIC + "\n")
        a = [f.to_json() for f in self.scan()]
        b = [f.to_json() for f in self.scan()]
        self.assertEqual(a, b)
        paths = [Finding.from_json(x).locations[0].path for x in a]
        # files of a directory first (sorted), then subdirectories (sorted)
        self.assertEqual(paths[::2], ["m.txt", "z.txt", "a/a.txt", "a/b.txt"])
        ids = [Finding.from_json(x).id for x in a]
        self.assertEqual(len(ids), len(set(ids)))
        for i in ids:
            self.assertRegex(i, r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")

    def test_protocols(self):
        self.assertIsInstance(SecretScanner(), Scanner)
        self.assertIsInstance(SecretValidator(), Validator)
        self.assertNotIsInstance(object(), Scanner)

    def test_unreadable_file(self):
        p = write(self.root, "a.txt", AWS)
        os.chmod(p, 0)
        self.addCleanup(os.chmod, p, 0o600)
        if os.access(p, os.R_OK):
            self.skipTest("running as a user that ignores permissions")
        sc = SecretScanner()
        self.assertEqual(list(sc.scan(self.root)), [])
        self.assertEqual(sc.stats.skipped_unreadable, 1)


class ValidatorTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.root = self._td.name
        write(self.root, "a.txt", "x\n" + AWS + "\n")
        self.v = SecretValidator(
            clock=lambda: datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc))

    def test_confirms(self):
        (f,) = SecretScanner().scan(self.root)
        out = self.v.validate(f, LocalContextReader(self.root))
        self.assertIs(out.status, Status.VALIDATED)
        self.assertIs(out.validation.method, ValidationMethod.TOOL_CONFIRMED)
        self.assertEqual(out.validation.validated_at, "2026-01-02T03:04:05Z")
        self.assertEqual(Finding.from_json(out.to_json()), out)
        self.assertNotIn(AWS, out.to_json())
        self.assertIs(f.status, Status.HYPOTHESIS)

    def test_reader_exception_returns_none(self):
        (f,) = SecretScanner().scan(self.root)

        def boom(path):
            raise RuntimeError("x")
        self.assertIsNone(self.v.validate(f, boom))

    def test_unchanged_when_gone_or_handled(self):
        (f,) = SecretScanner().scan(self.root)
        write(self.root, "a.txt", "nothing\n")
        reader = LocalContextReader(self.root)
        self.assertIsNone(self.v.validate(f, reader))
        os.remove(os.path.join(self.root, "a.txt"))
        self.assertIsNone(self.v.validate(f, reader))
        self.assertIsNone(self.v.validate(f, lambda p: None))

    def test_reader_refuses_escape_and_symlinks(self):
        out = tempfile.mkdtemp()
        self.addCleanup(os.rmdir, out)
        reader = LocalContextReader(self.root)
        self.assertIsNone(reader("../x"))
        self.assertIsNone(reader("/etc/passwd"))
        os.symlink(out, os.path.join(self.root, "ld"))
        self.assertIsNone(reader("ld/x"))
        os.symlink("a.txt", os.path.join(self.root, "l.txt"))
        self.assertIsNone(reader("l.txt"))
        self.assertIsNone(reader("a\x00.txt"))
        self.assertIsNone(reader("a\\b"))
        self.assertIsNone(reader("x" * 5000))


if __name__ == "__main__":
    unittest.main()
