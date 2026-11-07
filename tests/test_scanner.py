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
        lines = ['password = "changeme123"', 'api_key = "your-api-key-here"',
                 'secret: "<your-secret-value>"', 'token = "example_token_value"',
                 'password = "${DB_PASSWORD}"', 'api_key = "xxxxxxxxxxxx"',
                 'secret = "short"']
        write(self.root, "a.py", "\n".join(lines) + "\n")
        self.assertEqual(self.scan(), [])

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
        for name in ("bad\nname.txt", "back\\slash.txt", "bidi‮name.txt"):
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


if __name__ == "__main__":
    unittest.main()
