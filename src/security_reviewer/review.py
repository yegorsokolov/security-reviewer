"""Shared scan pipeline used by the ``review`` and ``benchmark`` commands.

Secret scanning and source-based vulnerability detection are independent;
both emit schema_version 1 findings distinguished by rule id
(``secret.<rule>.<hash>`` / ``vuln.<rule>.<hash>``).
"""
from __future__ import annotations

import dataclasses
import os
from dataclasses import dataclass

from .secret_scanner import (
    RULES as SECRET_RULES, LocalContextReader, SecretScanner, SecretValidator,
)
from .vuln_detectors import DETECTORS, VulnScanner

LIMITS = ("max_file_size", "max_files", "max_total_bytes", "max_findings",
          "max_line_length", "max_entries", "max_depth")


class ReviewError(Exception):
    """PATH cannot be read."""


def finding_sort_key(f):
    loc = f.locations[0] if f.locations else None
    return (loc.path if loc else "", loc.start_line if loc else 0,
            (loc.start_column or 0) if loc else 0, f.id)


def rule_of(finding):
    """Rule id encoded in a finding id (``<kind>.<rule>.<hash>``)."""
    parts = finding.id.split(".")
    return parts[1] if len(parts) == 3 else ""


@dataclass
class ScanResult:
    findings: list
    stats: dict
    limits: dict
    coverage: dict
    secret_scanner: object = None
    primary: object = None


def scan_tree(path, *, secrets=True, vuln=True, limits=None, validator=None):
    """Scan directory ``path``. Raises ReviewError when it cannot be read."""
    limits = limits or {}
    findings, primary, secret_sc, vuln_sc = [], None, None, None
    try:
        if secrets:
            secret_sc = SecretScanner(**limits)
            findings += list(secret_sc.scan(path))
            primary = secret_sc
        if vuln:
            vuln_sc = VulnScanner(**limits)
            findings += list(vuln_sc.scan(path))
            primary = primary or vuln_sc
    except (OSError, ValueError):
        raise ReviewError("cannot read PATH") from None
    st = primary.stats
    if st.skipped_unreadable and not st.entries_visited \
            and not st.files_scanned:
        raise ReviewError("cannot read PATH")  # root could not be opened
    if validator is not None and secrets:
        reader = LocalContextReader(path, max_file_size=primary.max_file_size)
        findings = [validator.validate(f, reader) or f for f in findings]
    findings.sort(key=finding_sort_key)
    stats = dataclasses.asdict(st)
    stats.pop("skip_samples", None)  # may contain paths
    cov = {
        "rules_run": {
            "secret": sorted(r.id for r in SECRET_RULES) if secrets else [],
            "vulnerability": sorted(DETECTORS) if vuln else [],
        },
        "source_detectors_ran": bool(vuln),
        "files_seen": dict(sorted(vuln_sc.coverage["files_seen"].items()))
        if vuln else {},
        "files_parsed": vuln_sc.coverage["files_parsed"] if vuln else 0,
        "unsupported": dict(vuln_sc.coverage["unsupported"]) if vuln
        else {"unparseable": 0, "unsupported_language": 0},
    }
    return ScanResult(findings, stats,
                      {k: getattr(primary, k) for k in LIMITS}, cov,
                      secret_sc, primary)


__all__ = ["LIMITS", "ReviewError", "ScanResult", "scan_tree", "rule_of",
           "finding_sort_key", "SecretValidator"]
