"""Benchmark harness: scores 'source-only' and 'advisory-assisted' separately.

The manifest (JSON, schema 1) holds the labels. Only this scorer reads them:
the scanner is handed nothing but the snapshot directory. Snapshots and
labels live outside the repository. A baseline file is compared with zero
tolerance and is only ever written by an explicit ``--write-baseline``.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from fractions import Fraction

from . import advisories as adv
from .review import ReviewError, rule_of, scan_tree

SCHEMA = 1
MODES = ("source-only", "advisory-assisted")
SPLITS = ("dev", "heldout")
ROLES = ("vulnerable", "fixed", "control", "lookalike")
LINE_TOLERANCE = 2
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
EXIT_OK, EXIT_FAIL, EXIT_USAGE = 0, 1, 2


class BenchmarkError(Exception):
    """Usage/input error (exit 2)."""


# ---------------------------------------------------------------- manifest
def _req(cond, msg):
    if not cond:
        raise BenchmarkError(f"invalid manifest: {msg}")


def _is_str(v):
    return isinstance(v, str) and v != ""


def load_manifest(path):
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_MANIFEST_BYTES + 1)
        _req(len(raw) <= MAX_MANIFEST_BYTES, "too large")
        doc = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, RecursionError):
        raise BenchmarkError("cannot read manifest") from None
    _req(isinstance(doc, dict) and doc.get("schema") == SCHEMA,
         "schema must be 1")
    cases = doc.get("cases")
    _req(isinstance(cases, list), "cases must be a list")
    seen = set()
    for c in cases:
        _req(isinstance(c, dict), "case must be an object")
        cid = c.get("id")
        _req(_is_str(cid) and cid not in seen, "case id missing or duplicate")
        seen.add(cid)
        _req(c.get("split") in SPLITS, f"{cid}: bad split")
        _req(c.get("role") in ROLES, f"{cid}: bad role")
        snap = c.get("snapshot")
        _req(_is_str(snap) and not os.path.isabs(snap) and "\\" not in snap
             and not {"", ".", ".."} & set(snap.split("/")),
             f"{cid}: bad snapshot path")
        exp = c.get("expected")
        _req(isinstance(exp, list), f"{cid}: expected must be a list")
        for e in exp:
            _req(isinstance(e, dict) and _is_str(e.get("rule"))
                 and _is_str(e.get("path"))
                 and type(e.get("line")) is int and e["line"] >= 1,
                 f"{cid}: bad expected entry")
        _req(bool(exp) == (c["role"] == "vulnerable"),
             f"{cid}: only vulnerable cases carry expected entries")
        a = c.get("advisory")
        if a is not None:
            _req(isinstance(a, dict) and _is_str(a.get("id"))
                 and _is_str(a.get("affected")) and _is_str(c.get("version"))
                 and _is_str(c.get("package") or c.get("product")),
                 f"{cid}: advisory needs id, affected, version, package")
            try:
                adv.parse_range(a["affected"])
                adv.parse_version(c["version"])
                if a.get("fixed"):
                    adv.parse_version(a["fixed"])
            except adv.AdvisoryError:
                raise BenchmarkError(
                    f"invalid manifest: {cid}: bad version or range") from None
    return doc


def _inside(path, directory):
    path, directory = os.path.realpath(path), os.path.realpath(directory)
    return path == directory or path.startswith(directory.rstrip(os.sep)
                                                + os.sep)


def check_outside_snapshots(manifest, root, files):
    """The manifest and every file we read or write must not live inside a
    snapshot (the scanner would read it, or a write would alter the data)."""
    for c in manifest["cases"]:
        snap = os.path.join(root, c["snapshot"])
        for f in files:
            if f and _inside(f, snap):
                raise BenchmarkError(
                    f"{c['id']}: manifest, baseline and output files must "
                    "not be inside a snapshot")


def _snapshot_dir(root, case):
    real_root = os.path.realpath(root)
    p = os.path.join(root, case["snapshot"])
    if os.path.islink(p) or not os.path.isdir(p) \
            or os.path.realpath(p) == real_root or not (
            os.path.realpath(p) + os.sep).startswith(real_root + os.sep):
        raise BenchmarkError(f"{case['id']}: snapshot is not a plain "
                             "directory inside --root")
    return p


# ----------------------------------------------------------------- scoring
def _matches(finding, exp):
    return (finding["rule"] == exp["rule"] and finding["path"] == exp["path"]
            and abs(finding["line"] - exp["line"]) <= LINE_TOLERANCE)


def score_case(case, found):
    """tp = expected entries matched by >=1 finding, fn = unmatched entries,
    fp = findings matching no expected entry."""
    exp = case["expected"]
    tp = sum(1 for e in exp if any(_matches(f, e) for f in found))
    fp = [f for f in found if not any(_matches(f, e) for e in exp)]
    return {"tp": tp, "fn": len(exp) - tp, "fp": len(fp)}, fp


def _ratio(num, den):
    return round(num / den, 6) if den else None


def _case_advisory(case):
    a = case.get("advisory")
    if not a:
        return None
    name = adv.normalize_package(case.get("package") or case["product"])
    status = adv.classify(case["version"], a["affected"], a.get("fixed"))
    return {"id": a["id"], "package": name, "version": case["version"],
            "status": status, "in_range": status == "affected",
            "cwe": a.get("cwe")}


def _scan_case(root, case):
    snap = _snapshot_dir(root, case)  # the scanner gets only this path
    t0 = time.perf_counter()
    try:
        res = scan_tree(snap)
    except ReviewError:
        raise BenchmarkError(f"{case['id']}: cannot read snapshot") from None
    ms = int((time.perf_counter() - t0) * 1000)
    found = []
    for f in res.findings:
        loc = f.locations[0]
        found.append({"rule": rule_of(f), "path": loc.path,
                      "line": loc.start_line, "cwe": f.cwe})
    found.sort(key=lambda d: (d["path"], d["line"], d["rule"]))
    return found, res.coverage, ms


def _mode_section(mode, cases, runs, deterministic):
    totals = {"tp": 0, "fp": 0, "fn": 0}
    alarms = {"fixed": 0, "lookalike": 0, "control": 0}
    unsup = {"unparseable": 0, "unsupported_language": 0}
    out_cases, runtime = {}, 0
    ad = {"cases_with_advisory": 0, "in_range_cases": 0,
          "advisory_only_detections": 0, "advisory_false_alarms": 0,
          "corroborated_tp": 0, "uncorroborated_tp": 0,
          "corroborated_fp": 0}
    for c in cases:
        found, cov, ms = runs[c["id"]]
        sc, fps = score_case(c, found)
        for k in totals:
            totals[k] += sc[k]
        if c["role"] in alarms:
            alarms[c["role"]] += len(found)
        for k in unsup:
            unsup[k] += cov["unsupported"][k]
        runtime += ms
        entry = {"role": c["role"], "split": c["split"], **sc,
                 "findings": len(found),
                 "expected": sorted([e["rule"], e["path"], e["line"]]
                                    for e in c["expected"]),
                 "unsupported": dict(cov["unsupported"]),
                 "files_parsed": cov["files_parsed"],
                 "found": [[f["rule"], f["path"], f["line"]]
                           for f in found[:50]]}
        if not deterministic:
            entry["runtime_ms"] = ms
        if mode == "advisory-assisted":
            a = _case_advisory(c)
            entry["advisory"] = a
            if a:
                ad["cases_with_advisory"] += 1
                ad["in_range_cases"] += a["in_range"]
                if a["in_range"]:
                    corr = [f for f in found if a["cwe"] in (None, f["cwe"])]
                    tp_f = [f for f in found if any(
                        _matches(f, e) for e in c["expected"])]
                    ctp = sum(1 for f in tp_f if f in corr)
                    ad["corroborated_tp"] += ctp
                    ad["uncorroborated_tp"] += len(tp_f) - ctp
                    ad["corroborated_fp"] += sum(
                        1 for f in fps if f in corr)
                    if c["role"] == "vulnerable" and sc["fn"]:
                        ad["advisory_only_detections"] += 1
                    if c["role"] != "vulnerable":
                        ad["advisory_false_alarms"] += 1
                    entry["corroborated_findings"] = len(corr)
        out_cases[c["id"]] = entry
    sec = {"overall": {**totals,
                       "precision": _ratio(totals["tp"],
                                           totals["tp"] + totals["fp"]),
                       "recall": _ratio(totals["tp"],
                                        totals["tp"] + totals["fn"])},
           "false_alarms_by_role": alarms, "unsupported": unsup,
           "cases": out_cases}
    if mode == "advisory-assisted":
        sec["advisory"] = ad
    if not deterministic:
        sec["overall"]["runtime_ms"] = runtime
    return sec


def run_benchmark(manifest, root, split="dev", mode="both",
                  deterministic=False):
    cases = [c for c in manifest["cases"] if split == "all"
             or c["split"] == split]
    cases.sort(key=lambda c: c["id"])
    runs = {c["id"]: _scan_case(root, c) for c in cases}
    modes = MODES if mode == "both" else (mode,)
    return {
        "schema_version": 1, "tool": "security-reviewer-benchmark",
        "split": split, "case_count": len(cases),
        "deterministic": deterministic,
        "match_rule": {"rule_and_path_equal": True,
                       "line_tolerance": LINE_TOLERANCE},
        "modes": {m: _mode_section(m, cases, runs, deterministic)
                  for m in modes},
    }


# ---------------------------------------------------------------- baseline
def baseline_of(report):
    """Score-only view of a report (no runtimes, no file lists)."""
    modes = {}
    for m, sec in report["modes"].items():
        o = sec["overall"]
        cases = {}
        for cid, c in sec["cases"].items():
            cases[cid] = {"role": c["role"], "expected": c["expected"],
                          "tp": c["tp"], "fp": c["fp"]}
            if "advisory" in c:
                a = c["advisory"]
                cases[cid]["advisory"] = None if a is None else {
                    "status": a["status"], "in_range": a["in_range"]}
        modes[m] = {"overall": {k: o[k] for k in ("tp", "fp", "fn")},
                    "cases": cases}
        if "advisory" in sec:
            modes[m]["advisory"] = dict(sec["advisory"])
    return {"schema_version": 1, "split": report["split"], "modes": modes}


def _frac(num, den):
    return Fraction(num, den) if den else None


def _pr(o):
    return (_frac(o["tp"], o["tp"] + o["fp"]),
            _frac(o["tp"], o["tp"] + o["fn"]))


_AD_KEYS = ("advisory_false_alarms", "corroborated_tp")


def _is_count(v):
    return type(v) is int and v >= 0


def _check_base_mode(base):
    """Validate one baseline mode section; return (cases, overall)."""
    try:
        cases, overall = base["cases"], base["overall"]
        ok = isinstance(cases, dict) and isinstance(overall, dict) \
            and all(_is_count(overall[k]) for k in ("tp", "fp", "fn"))
        for c in cases.values() if ok else ():
            ok = ok and isinstance(c, dict) \
                and isinstance(c["role"], str) \
                and isinstance(c["expected"], list) \
                and all(isinstance(e, list) for e in c["expected"]) \
                and _is_count(c["tp"]) and _is_count(c["fp"]) \
                and ("advisory" not in c or c["advisory"] is None
                     or (isinstance(c["advisory"], dict)
                         and isinstance(c["advisory"].get("status"), str)
                         and isinstance(c["advisory"].get("in_range"), bool)))
        ad = base.get("advisory")
        ok = ok and (ad is None or (isinstance(ad, dict) and all(
            _is_count(ad.get(k)) for k in _AD_KEYS)))
    except (KeyError, TypeError, AttributeError):
        ok = False
    if not ok:
        raise BenchmarkError("invalid baseline file")
    return cases, overall


def _sums(cases):
    tp = sum(c["tp"] for c in cases.values())
    fp = sum(c["fp"] for c in cases.values())
    fn = sum(len(c["expected"]) - c["tp"] for c in cases.values())
    return {"tp": tp, "fp": fp, "fn": fn}


def compare(baseline, report):
    """List of regression messages (empty if none). Zero tolerance."""
    if not isinstance(baseline, dict) or baseline.get("schema_version") != 1 \
            or not isinstance(baseline.get("modes"), dict):
        raise BenchmarkError("invalid baseline file")
    if baseline.get("split") != report["split"]:
        raise BenchmarkError("baseline was written for split "
                             f"{baseline.get('split')!r}, not "
                             f"{report['split']!r}")
    out = []
    for m, sec in sorted(report["modes"].items()):
        base = baseline["modes"].get(m)
        if base is None:
            raise BenchmarkError(f"baseline has no scores for mode {m!r}")
        if not isinstance(base, dict):
            raise BenchmarkError("invalid baseline file")
        bcases, boverall = _check_base_mode(base)
        # Totals must agree with the per-case numbers on both sides; the
        # (stricter) per-case sums are what is compared.
        bsum = _sums(bcases)
        if {k: boverall[k] for k in bsum} != bsum:
            out.append(f"[{m}] baseline overall does not match its cases "
                       "(tampered?)")
        if {k: sec["overall"][k] for k in bsum} != _sums(sec["cases"]):
            out.append(f"[{m}] report overall does not match its cases")
        bp, br = _pr(bsum)
        cp, cr = _pr(_sums(sec["cases"]))
        for name, b, c in (("precision", bp, cp), ("recall", br, cr)):
            if b is not None and (c is None or c < b):
                out.append(f"[{m}] {name} regressed: "
                           f"{_f(b)} -> {_f(c)}")
        bad, cad = base.get("advisory"), sec.get("advisory")
        if bad is not None:
            if cad is None:
                out.append(f"[{m}] advisory scores missing from current run")
            else:
                if cad["advisory_false_alarms"] > bad["advisory_false_alarms"]:
                    out.append(f"[{m}] advisory_false_alarms "
                               f"{bad['advisory_false_alarms']} -> "
                               f"{cad['advisory_false_alarms']}")
                if cad["corroborated_tp"] < bad["corroborated_tp"]:
                    out.append(f"[{m}] corroborated_tp "
                               f"{bad['corroborated_tp']} -> "
                               f"{cad['corroborated_tp']}")
        for cid, b in sorted(bcases.items()):
            c = sec["cases"].get(cid)
            if c is None:
                out.append(f"[{m}] case {cid}: missing from current run")
                continue
            if c["role"] != b["role"]:
                out.append(f"[{m}] case {cid}: role changed "
                           f"{b['role']} -> {c['role']}")
            missing = [e for e in b["expected"] if e not in c["expected"]]
            if missing:
                out.append(f"[{m}] case {cid}: expectations weakened or "
                           f"changed: {missing}")
            if c["tp"] < b["tp"]:
                out.append(f"[{m}] case {cid}: TP {b['tp']} -> {c['tp']}")
            if b["role"] != "vulnerable" and c["fp"] > b["fp"]:
                out.append(f"[{m}] case {cid}: false positives "
                           f"{b['fp']} -> {c['fp']} on a {b['role']} case")
            if "advisory" in b:
                ba, ca = b["advisory"], c.get("advisory")
                bs = ba["status"] if ba else None
                cs = ca["status"] if ca else None
                if bs != cs:
                    out.append(f"[{m}] case {cid}: advisory status "
                               f"{bs} -> {cs}")
                if b["role"] != "vulnerable" and ca and ca["in_range"] \
                        and not (ba and ba["in_range"]):
                    out.append(f"[{m}] case {cid}: {b['role']} case flipped "
                               "to in_range")
    return out


def _f(x):
    return "none" if x is None else f"{float(x):.6f}"


def failed_expectations(report):
    """Missed expected entries and false alarms on non-vulnerable cases."""
    out = []
    for m, sec in sorted(report["modes"].items()):
        for cid, c in sorted(sec["cases"].items()):
            if c["fn"]:
                out.append(f"[{m}] case {cid}: {c['fn']} expected "
                           "finding(s) not found")
            if c["role"] != "vulnerable" and c["findings"]:
                out.append(f"[{m}] case {cid}: {c['findings']} finding(s) "
                           f"on a {c['role']} case")
    return out


# --------------------------------------------------------------------- CLI
def add_arguments(sub):
    b = sub.add_parser("benchmark", help="score detectors on a labelled "
                       "benchmark (labels and snapshots stay outside the repo)")
    b.add_argument("manifest", metavar="MANIFEST")
    b.add_argument("--root", required=True, metavar="BENCH_ROOT",
                   help="directory the manifest's snapshot paths are under")
    b.add_argument("--split", choices=(*SPLITS, "all"), default="dev")
    b.add_argument("--mode", choices=(*MODES, "both"), default="both")
    b.add_argument("--baseline", metavar="FILE",
                   help="compare with FILE; exit 1 on any regression")
    b.add_argument("--write-baseline", metavar="FILE",
                   help="write the current scores to FILE (explicit only)")
    b.add_argument("--output", metavar="FILE",
                   help="write the report to FILE instead of stdout")
    b.add_argument("--deterministic", action="store_true",
                   help="omit runtimes so output is byte-reproducible")


def _dump(obj):
    return json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=True) + "\n"


def _write(path, text):
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    except OSError:
        raise BenchmarkError("cannot write output file") from None


def run(args):
    err = sys.stderr.write
    try:
        manifest = load_manifest(args.manifest)
        if not os.path.isdir(args.root):
            raise BenchmarkError("--root is not a directory")
        check_outside_snapshots(manifest, args.root,
                                (args.manifest, args.baseline,
                                 args.write_baseline, args.output))
        report = run_benchmark(manifest, args.root, args.split, args.mode,
                               args.deterministic)
        with open(args.manifest, "rb") as fh:
            report["manifest_sha256"] = hashlib.sha256(fh.read()).hexdigest()
        problems = None
        if args.baseline:
            try:
                with open(args.baseline, "rb") as fh:
                    raw = fh.read(MAX_MANIFEST_BYTES + 1)
                if len(raw) > MAX_MANIFEST_BYTES:
                    raise ValueError
                base = json.loads(raw.decode())
            except (OSError, ValueError, RecursionError):
                raise BenchmarkError("cannot read baseline") from None
            problems = compare(base, report)
            report["regressions"] = problems
        else:
            problems = failed_expectations(report)
            report["failed_expectations"] = problems
        if args.write_baseline and not (args.baseline and problems):
            _write(args.write_baseline, _dump(baseline_of(report)))
        text = _dump(report)
        if args.output:
            _write(args.output, text)
        else:
            sys.stdout.write(text)
    except BenchmarkError as exc:
        err(f"security-reviewer: error: {exc}\n")
        return EXIT_USAGE
    for p in problems:
        err(f"security-reviewer: benchmark: {p}\n")
    return EXIT_FAIL if problems else EXIT_OK
