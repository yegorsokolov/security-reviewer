"""Offline, static, defensive review CLI.

Runs the local SecretScanner (and optionally SecretValidator) over a
directory and prints one deterministic, redacted JSON document. It reads
files as data only: nothing is executed or imported. By default nothing is
sent anywhere; ``--ai-report`` is an explicit opt-in to a loopback-only local
model (see local_report.py).
"""
import argparse
import json
import math
import os
import re
import sys
from datetime import datetime, timezone

from . import SCHEMA_VERSION, advisories, benchmark, local_report
from .review import LIMITS, ReviewError, scan_tree
from .secret_scanner import SecretValidator

TOOL = "security-reviewer"
#: Fixed validation timestamp used when neither --timestamp nor
#: SOURCE_DATE_EPOCH is given, so output is byte-reproducible.
DEFAULT_TIMESTAMP = "1970-01-01T00:00:00Z"
EXIT_OK, EXIT_FINDINGS, EXIT_USAGE = 0, 1, 2

_LIMITS = LIMITS


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


def _positive_seconds(text):
    try:
        v = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a positive number")
    if not math.isfinite(v) or v <= 0:
        raise argparse.ArgumentTypeError("must be a positive number")
    return v


_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}")


def _model_name(text):
    if not _MODEL_RE.fullmatch(text):
        raise argparse.ArgumentTypeError("invalid model name")
    if local_report.is_cloud_name(text):
        raise argparse.ArgumentTypeError(
            "cloud (remote) models are not allowed")
    return text


_AI_OPTS = ("ai_model", "ai_endpoint", "ai_timeout", "ai_num_ctx",
            "ai_max_tokens")


def _timestamp(text):
    try:
        dt = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise argparse.ArgumentTypeError("must look like 2026-01-02T03:04:05Z")
    return dt.replace(tzinfo=timezone.utc)


_MAX_EPOCH = 253402300799  # 9999-12-31T23:59:59Z: keeps a 4-digit year


def _default_clock():
    """Clock from SOURCE_DATE_EPOCH, or None if it is set but invalid."""
    sde = os.environ.get("SOURCE_DATE_EPOCH", "")
    if not sde:
        return datetime.strptime(DEFAULT_TIMESTAMP, "%Y-%m-%dT%H:%M:%SZ"
                                 ).replace(tzinfo=timezone.utc)
    try:
        v = int(sde)
        if not 0 <= v <= _MAX_EPOCH:
            return None
        return datetime.fromtimestamp(v, timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def build_parser():
    p = _Parser(prog="security-reviewer",
                description="Offline static review: secrets and source vulnerabilities.")
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")
    r = sub.add_parser("review", help="scan a local checkout directory")
    r.add_argument("path", metavar="PATH", help="directory to scan")
    r.add_argument("--no-validate", action="store_true",
                   help="skip the validator; findings stay 'hypothesis'")
    r.add_argument("--no-secrets", action="store_true",
                   help="do not run the secret scanner")
    r.add_argument("--no-vuln", action="store_true",
                   help="do not run the source vulnerability detectors")
    r.add_argument("--advisories", metavar="FILE",
                   help="local JSON list of advisories (id, package, "
                        "affected, fixed, cwe); matches are reported "
                        "separately from findings")
    r.add_argument("--package", action="append", default=[],
                   metavar="NAME=VERSION",
                   help="declared package version to match against "
                        "--advisories (repeatable)")
    r.add_argument("--output", metavar="FILE",
                   help="write the JSON report to FILE instead of stdout")
    r.add_argument("--fail-on-findings", action="store_true",
                   help="exit 1 when any finding is reported")
    r.add_argument("--timestamp", type=_timestamp, metavar="ISO8601Z",
                   help="validated_at value (default: SOURCE_DATE_EPOCH or a "
                        "fixed epoch placeholder, for reproducible output)")
    r.add_argument("--ai-report", action="store_true",
                   help="opt in: send a bounded, sanitised summary of the "
                        "findings to a LOCAL model (loopback Ollama) and add "
                        "a non-authoritative top-level ai_report")
    r.add_argument("--ai-model", type=_model_name, metavar="NAME",
                   help="model name (default: "
                        f"{local_report.DEFAULT_MODEL})")
    r.add_argument("--ai-endpoint", metavar="URL",
                   help="loopback http URL (default: "
                        f"{local_report.DEFAULT_ENDPOINT})")
    r.add_argument("--ai-timeout", type=_positive_seconds, metavar="SECONDS",
                   help="hard overall deadline for the model step (default: "
                        f"{local_report.DEFAULT_TIMEOUT:g})")
    r.add_argument("--ai-num-ctx", type=_positive, metavar="N",
                   help="model context size (default: "
                        f"{local_report.DEFAULT_NUM_CTX})")
    r.add_argument("--ai-max-tokens", type=_positive, metavar="N",
                   help="max generated tokens (default: "
                        f"{local_report.DEFAULT_MAX_TOKENS})")
    for name in _LIMITS:
        r.add_argument("--" + name.replace("_", "-"), dest=name,
                       type=_positive, metavar="N",
                       help="scanner limit (default: scanner default)")
    benchmark.add_arguments(sub)
    return p


def _fail(msg):
    sys.stderr.write(f"security-reviewer: error: {msg}\n")
    return EXIT_USAGE


def _review(args):
    path = args.path
    if not os.path.isdir(path):
        return _fail("PATH is not an existing directory")
    if not os.access(path, os.R_OK | os.X_OK):
        return _fail("cannot read PATH")
    default_now = None
    if not args.no_validate and not args.timestamp:
        default_now = _default_clock()
        if default_now is None:
            return _fail("SOURCE_DATE_EPOCH must be an integer between 0 "
                         f"and {_MAX_EPOCH}")
    if args.no_secrets and args.no_vuln:
        return _fail("--no-secrets and --no-vuln leave nothing to run")
    if args.package and not args.advisories:
        return _fail("--package requires --advisories")
    try:
        packages = [advisories.parse_package_spec(p) for p in args.package]
        advs = advisories.load_advisories(args.advisories) \
            if args.advisories else []
    except advisories.AdvisoryError as exc:
        return _fail(str(exc))
    ai_client = None
    if not args.ai_report:
        if any(getattr(args, k) is not None for k in _AI_OPTS):
            return _fail("--ai-* options require --ai-report")
    else:
        try:  # refuse an unsafe endpoint before scanning or building payloads
            ai_client = local_report.OllamaClient(
                args.ai_endpoint or local_report.DEFAULT_ENDPOINT,
                args.ai_timeout or local_report.DEFAULT_TIMEOUT)
        except local_report.EndpointError as exc:
            return _fail(f"--ai-endpoint: {exc}")
    limits = {k: getattr(args, k) for k in _LIMITS
              if getattr(args, k) is not None}
    validator = None
    if not args.no_validate:
        when = args.timestamp or default_now
        validator = SecretValidator(clock=lambda: when)
    try:
        res = scan_tree(path, secrets=not args.no_secrets,
                        vuln=not args.no_vuln, limits=limits,
                        validator=validator)
    except ReviewError:
        return _fail("cannot read PATH")
    findings = res.findings
    report = {
        "schema_version": 1,
        "finding_schema_version": SCHEMA_VERSION,
        "tool": TOOL,
        "root": ".",
        "validated": not args.no_validate,
        "findings": [f.to_dict() for f in findings],
        "advisory_matches": advisories.link_findings(
            advisories.match_advisories(advs, packages), findings),
        "coverage": res.coverage,
        "stats": res.stats,
        "limits": res.limits,
    }
    if ai_client is not None:
        report["ai_report"] = local_report.build_report(
            findings, ai_client,
            model=args.ai_model or local_report.DEFAULT_MODEL,
            num_ctx=args.ai_num_ctx or local_report.DEFAULT_NUM_CTX,
            max_tokens=args.ai_max_tokens or local_report.DEFAULT_MAX_TOKENS)
    text = json.dumps(report, sort_keys=True, indent=2,
                      ensure_ascii=True) + "\n"
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError:
            return _fail("cannot write --output file")
    else:
        try:
            sys.stdout.write(text)
            sys.stdout.flush()
        except BrokenPipeError:
            try:  # stop the interpreter's exit-time flush from failing too
                os.dup2(os.open(os.devnull, os.O_WRONLY),
                        sys.stdout.fileno())
            except (OSError, ValueError, AttributeError):
                pass
            return EXIT_USAGE
    return EXIT_FINDINGS if (findings and args.fail_on_findings) else EXIT_OK


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.command == "benchmark":
        return benchmark.run(args)
    return _review(args)
