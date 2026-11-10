"""Offline, static, defensive review CLI.

Runs the local SecretScanner (and optionally SecretValidator) over a
directory and prints one deterministic, redacted JSON document. It reads
files as data only: nothing is executed, imported or sent anywhere.
"""
import argparse
import dataclasses
import json
import os
import sys
from datetime import datetime, timezone

from . import SCHEMA_VERSION
from .secret_scanner import LocalContextReader, SecretScanner, SecretValidator

TOOL = "security-reviewer"
#: Fixed validation timestamp used when neither --timestamp nor
#: SOURCE_DATE_EPOCH is given, so output is byte-reproducible.
DEFAULT_TIMESTAMP = "1970-01-01T00:00:00Z"
EXIT_OK, EXIT_FINDINGS, EXIT_USAGE = 0, 1, 2

_LIMITS = ("max_file_size", "max_files", "max_total_bytes", "max_findings",
           "max_line_length", "max_entries", "max_depth")


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def _positive(text):
    try:
        v = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a positive integer")
    if v < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return v


def _timestamp(text):
    try:
        dt = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise argparse.ArgumentTypeError("must look like 2026-01-02T03:04:05Z")
    return dt.replace(tzinfo=timezone.utc)


def _default_clock():
    sde = os.environ.get("SOURCE_DATE_EPOCH", "")
    try:
        return datetime.fromtimestamp(int(sde), timezone.utc)
    except (ValueError, OverflowError, OSError):
        return datetime.strptime(DEFAULT_TIMESTAMP, "%Y-%m-%dT%H:%M:%SZ"
                                 ).replace(tzinfo=timezone.utc)


def build_parser():
    p = _Parser(prog="security-reviewer",
                description="Offline static review for hardcoded secrets.")
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")
    r = sub.add_parser("review", help="scan a local checkout directory")
    r.add_argument("path", metavar="PATH", help="directory to scan")
    r.add_argument("--no-validate", action="store_true",
                   help="skip the validator; findings stay 'hypothesis'")
    r.add_argument("--output", metavar="FILE",
                   help="write the JSON report to FILE instead of stdout")
    r.add_argument("--fail-on-findings", action="store_true",
                   help="exit 1 when any finding is reported")
    r.add_argument("--timestamp", type=_timestamp, metavar="ISO8601Z",
                   help="validated_at value (default: SOURCE_DATE_EPOCH or a "
                        "fixed epoch placeholder, for reproducible output)")
    for name in _LIMITS:
        r.add_argument("--" + name.replace("_", "-"), dest=name,
                       type=_positive, metavar="N",
                       help="scanner limit (default: scanner default)")
    return p


def _sort_key(f):
    loc = f.locations[0] if f.locations else None
    return (loc.path if loc else "", loc.start_line if loc else 0,
            (loc.start_column or 0) if loc else 0, f.id)


def _fail(msg):
    sys.stderr.write(f"security-reviewer: error: {msg}\n")
    return EXIT_USAGE


def _review(args):
    path = args.path
    if not os.path.isdir(path):
        return _fail("PATH is not an existing directory")
    limits = {k: getattr(args, k) for k in _LIMITS
              if getattr(args, k) is not None}
    scanner = SecretScanner(**limits)
    try:
        findings = list(scanner.scan(path))
    except (OSError, ValueError):
        return _fail("cannot read PATH")
    if not args.no_validate:
        clock = (lambda: args.timestamp) if args.timestamp else _default_clock
        validator = SecretValidator(clock=clock)
        reader = LocalContextReader(
            path, max_file_size=scanner.max_file_size)
        findings = [validator.validate(f, reader) or f for f in findings]
    findings.sort(key=_sort_key)
    stats = dataclasses.asdict(scanner.stats)
    stats.pop("skip_samples", None)  # may contain paths
    report = {
        "schema_version": 1,
        "finding_schema_version": SCHEMA_VERSION,
        "tool": TOOL,
        "root": ".",
        "validated": not args.no_validate,
        "findings": [f.to_dict() for f in findings],
        "stats": stats,
        "limits": {k: getattr(scanner, k) for k in _LIMITS},
    }
    text = json.dumps(report, sort_keys=True, indent=2,
                      ensure_ascii=True) + "\n"
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError:
            return _fail("cannot write --output file")
    else:
        sys.stdout.write(text)
    return EXIT_FINDINGS if (findings and args.fail_on_findings) else EXIT_OK


def main(argv=None):
    args = build_parser().parse_args(argv)
    return _review(args)
