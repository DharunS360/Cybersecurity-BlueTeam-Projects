"""Command-line interface:  python -m soar <command>"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from . import __version__
from .config import Settings
from .engine import Engine
from .ingest import from_indicators, from_text, load_alert
from .ioc import load_allowlist
from .models import CaseResult, Finding, IOCVerdict, Status

if os.name == "nt":
    os.system("")                     # enables ANSI colours in Windows 10/11 terminals

USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
COLORS = {"Malicious": "91", "Suspicious": "93", "Low Risk": "96", "Not Flagged": "92",
          "Unknown": "95", "Known Benign": "92", "Not Enriched": "90", "ok": "92", "fail": "91", "skip": "90"}


def c(text: str, color: str, bold: bool = False) -> str:
    if not USE_COLOR:
        return text
    return f"\033[{'1;' if bold else ''}{COLORS.get(color, color)}m{text}\033[0m"


def line(width: int = 100, ch: str = "-") -> str:
    return ch * width


# ------------------------------------------------------------------ rendering
def render_case(case: CaseResult, verbose: bool = False) -> None:
    a = case.alert
    print(c(f"\n{case.case_id}", "96", True) + f"   {a.title}")
    print(f"source: {a.source}   severity: {a.severity or '-'}   input sha256: {a.input_sha256[:16]}...")
    print(line(100, "="))
    print("OVERALL: " + c(f" {case.label.upper()} ", case.label, True) + f"  score {case.score}/100")
    print(line(100, "="))

    if not case.verdicts:
        print("No enrichable indicators were found in this input.")
    for v in sorted(case.verdicts, key=lambda x: -x.score):
        _render_verdict(v, verbose)

    if a.skipped:
        print(c("\nExcluded from enrichment (transparency log):", "90"))
        for s in a.skipped[:15]:
            print(f"  - {s['type']:<7} {s['value'][:70]:<70} {s['reason']}")
        if len(a.skipped) > 15:
            print(f"  ... and {len(a.skipped) - 15} more (see JSON export)")
    print()


def _render_verdict(v: IOCVerdict, verbose: bool) -> None:
    head = f"{v.ioc.type.value.upper():<6} {v.ioc.value[:64]}"
    print(f"\n{c(f'[{v.label}]', v.label, True):<22} {head}   score {v.score}  ({v.answered}/{v.applicable} sources answered)")
    if v.ioc.sources:
        print(c(f"   seen in: {', '.join(v.ioc.sources[:3])}", "90"))
    for f in v.findings:
        if f.status is Status.SKIPPED and not verbose:
            continue
        print("   " + _finding_line(f))
        if verbose and f.link:
            print(c(f"         verify: {f.link}", "90"))
    for n in v.notes:
        print(c(f"   note: {n}", "93" if "NOT" in n or "low confidence" in n else "90"))


def _finding_line(f: Finding) -> str:
    if f.status in (Status.OK, Status.NOT_FOUND):
        pts = f"+{f.points}" if f.points else " 0"
        tag = c(f"{pts:>4}", "91" if f.points >= 40 else "93" if f.points else "92")
        cache = c(" [cached]", "90") if f.cached else ""
        return f"{tag}  {f.provider:<15} {f.reason}{cache}"
    colour = "90" if f.status is Status.SKIPPED else "95"
    tag = c({"error": "ERR", "rate_limited": "RATE", "skipped": "SKIP"}.get(f.status.value, "?").rjust(4), colour)
    return f"{tag}  {f.provider:<15} {f.reason}"


# ------------------------------------------------------------------ commands
def cmd_analyze(args, settings: Settings) -> int:
    engine = Engine(settings)
    allow = load_allowlist(settings.allowlist_path)
    try:
        if args.file:
            alert = load_alert(args.file, allow, args.title)
        elif args.text:
            alert = from_text(args.text, "cli-text", args.title, allow)
        elif args.ioc:
            alert = from_indicators(args.ioc, allow)
        else:
            alert = from_text(sys.stdin.read(), "stdin", args.title, allow)
    except (FileNotFoundError, ValueError) as exc:
        print(c(f"error: {exc}", "91"), file=sys.stderr)
        return 1
    if not alert.iocs:
        print("No valid indicators found in the input.")
        for s in alert.skipped:
            print(f"  excluded: {s['type']} {s['value']} ({s['reason']})")
        return 0
    case = engine.analyze(alert, actor=os.environ.get("USERNAME") or os.environ.get("USER") or "analyst",
                          use_cache=not args.no_cache)
    render_case(case, args.verbose)
    if args.json:
        Path(args.json).write_text(json.dumps(case.to_dict(), indent=2), encoding="utf-8")
        print(f"JSON report written: {args.json}")
    return 2 if case.label == "Malicious" else 0     # non-zero exit lets scripts/CI react


def cmd_doctor(args, settings: Settings) -> int:
    engine = Engine(settings)
    print(c(f"\nSOAR doctor v{__version__} - live connectivity & key check", "96", True))
    print(f"data dir: {settings.data_dir}\n")
    from .models import IOC
    failures = 0
    for p in engine.providers:
        label = f"{p.name:<15}"
        if not p.enabled:
            print(f"  {c('SKIP', 'skip')}  {label} no API key set (optional)")
            continue
        ioc_type, value = p.probe
        t0 = time.monotonic()
        f = engine.query(p, IOC(ioc_type, value), use_cache=False)
        ms = (time.monotonic() - t0) * 1000
        if f.answered:
            print(f"  {c('PASS', 'ok')}  {label} {ms:6.0f} ms   probe {value[:20]}...")
        else:
            failures += 1
            print(f"  {c('FAIL', 'fail')}  {label} {f.reason}")
    print()
    print("All enabled sources are working." if not failures else c(f"{failures} source(s) failing - fix before trusting results.", "91"))
    return 1 if failures else 0


def cmd_verify(args, settings: Settings) -> int:
    ok, n, broken = Engine(settings).store.verify_audit()
    if ok:
        print(c(f"AUDIT LOG INTACT - {n} entries verified (hash chain valid).", "92", True))
        return 0
    print(c(f"AUDIT LOG TAMPERED - chain breaks at entry #{broken} (checked {n}).", "91", True))
    return 3


def cmd_cases(args, settings: Settings) -> int:
    rows = Engine(settings).store.list_cases(args.limit)
    if not rows:
        print("No cases yet. Run:  python -m soar analyze --ioc <indicator>")
        return 0
    print(f"{'CASE ID':<22}{'CREATED (UTC)':<26}{'VERDICT':<13}{'SCORE':<7}TITLE")
    for r in rows:
        verdict = c(r["label"].ljust(13), r["label"])
        print(f"{r['id']:<22}{r['created_at'][:19]:<26}{verdict}{r['score']:<7}{r['title'][:40]}")
    return 0


def cmd_show(args, settings: Settings) -> int:
    engine = Engine(settings)
    data = engine.store.get_case(args.case_id)
    if not data:
        print(c(f"case {args.case_id} not found", "91"), file=sys.stderr)
        return 1
    if args.audit:
        for e in engine.store.audit_entries(args.case_id):
            print(f"#{e['seq']:<4} {e['ts']}  {e['actor']:<10} {e['action']:<14} {e['detail_json'][:110]}")
    else:
        print(json.dumps(data, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="soar", description="SOAR Playbook Automation - enrichment & verdict engine")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="enrich and score indicators from a file, text, or stdin")
    src = a.add_mutually_exclusive_group()
    src.add_argument("--file", "-f", help=".eml / .json / .jsonl / .csv / .log / .txt")
    src.add_argument("--text", "-t", help="raw text to scan for indicators")
    src.add_argument("--ioc", "-i", nargs="+", help="one or more indicators (IP, domain, URL, hash, CVE)")
    a.add_argument("--title", help="override the case title")
    a.add_argument("--json", help="write a full JSON report to this path")
    a.add_argument("--no-cache", action="store_true", help="force fresh lookups")
    a.add_argument("--verbose", "-v", action="store_true", help="show skipped sources and verification links")
    a.set_defaults(fn=cmd_analyze)

    sub.add_parser("doctor", help="test every configured source live").set_defaults(fn=cmd_doctor)
    sub.add_parser("verify-audit", help="verify the audit log hash chain").set_defaults(fn=cmd_verify)
    cs = sub.add_parser("cases", help="list recent cases")
    cs.add_argument("--limit", type=int, default=20)
    cs.set_defaults(fn=cmd_cases)
    sh = sub.add_parser("show", help="show a stored case (JSON) or its audit trail")
    sh.add_argument("case_id")
    sh.add_argument("--audit", action="store_true")
    sh.set_defaults(fn=cmd_show)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args, Settings.load())