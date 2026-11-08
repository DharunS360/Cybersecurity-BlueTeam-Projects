#!/usr/bin/env python3
"""SysmonHunter - Windows Event / Sysmon threat hunter (Project 07)."""
import argparse
import csv
import glob
import json
import os
import sys
from datetime import datetime

from sysmonhunter import __version__
from sysmonhunter.demo import generate
from sysmonhunter.engine import analyze
from sysmonhunter.parser import LIVE_CHANNELS, is_admin, read_evtx, read_live
from sysmonhunter.report import write_report
from sysmonhunter.rules import SEV_ORDER, catalog

C = {"Critical": "\033[91m", "High": "\033[38;5;208m", "Medium": "\033[93m", "Low": "\033[92m",
     "dim": "\033[90m", "cyan": "\033[96m", "end": "\033[0m"}

BANNER = r"""
  ____                                _   _             _
 / ___| _   _ ___ _ __ ___   ___  _ __| | | |_   _ _ __ | |_ ___ _ __
 \___ \| | | / __| '_ ` _ \ / _ \| '_ \ |_| | | | | '_ \| __/ _ \ '__|
  ___) | |_| \__ \ | | | | | (_) | | | |  _  | |_| | | | | ||  __/ |
 |____/ \__, |___/_| |_| |_|\___/|_| |_|_| |_|\__,_|_| |_|\__\___|_|
        |___/   Windows Event + Sysmon Threat Hunter  v%s
""" % __version__


def main():
    os.system("")  # enable ANSI colours on Windows terminals
    ap = argparse.ArgumentParser(prog="hunter", description="Hunt for ATT&CK-mapped threats in Windows logs.")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--demo", action="store_true", help="analyse a built-in simulated attack (no setup needed)")
    mode.add_argument("--live", action="store_true", help="analyse this machine's event logs (run as Administrator)")
    mode.add_argument("--evtx", nargs="+", metavar="PATH", help="analyse .evtx file(s) or folder(s)")
    ap.add_argument("--max", type=int, default=3000, help="max events per channel in --live mode (default 3000)")
    ap.add_argument("--out", default="reports", help="output folder (default: reports)")
    ap.add_argument("--no-open", action="store_true", help="do not open the HTML report")
    ap.add_argument("--rules", action="store_true", help="list detection rules and exit")
    args = ap.parse_args()

    print(C["cyan"] + BANNER + C["end"])
    if args.rules:
        for r in catalog():
            print("%-9s %-8s %-10s %-22s %s" % (r["id"], r["severity"], r["technique"], r["tactic"], r["name"]))
        return 0
    if not (args.demo or args.live or args.evtx):
        args.demo = True
        print(C["dim"] + "[i] No mode given - running --demo. Use --live or --evtx for real data." + C["end"])

    events, source = [], ""
    if args.demo:
        events, source = generate(), "Demo dataset (simulated intrusion)"
    elif args.live:
        source = "Live logs: " + os.environ.get("COMPUTERNAME", "localhost")
        if not is_admin():
            print(C["Medium"] + "[!] Not running as Administrator - Security log will likely be unreadable." + C["end"])
        for ch in LIVE_CHANNELS:
            evs, err = read_live(ch, args.max)
            if err:
                print(C["Medium"] + "[!] %s: %s" % (ch, err.splitlines()[0] if err else "error") + C["end"])
            else:
                print("[+] %-45s %6d events" % (ch, len(evs)))
            events += evs
    else:
        source = "EVTX: " + ", ".join(args.evtx)
        files = []
        for p in args.evtx:
            files += glob.glob(os.path.join(p, "*.evtx")) if os.path.isdir(p) else [p]
        for fpath in files:
            if not os.path.isfile(fpath):
                print(C["Medium"] + "[!] Not found: " + fpath + C["end"])
                continue
            evs = read_evtx(fpath)
            print("[+] %-45s %6d events" % (os.path.basename(fpath), len(evs)))
            events += evs

    if not events:
        print(C["Critical"] + "[x] No events loaded. Try: python hunter.py --demo" + C["end"])
        return 1

    findings = analyze(events)
    out_dir = args.out if os.path.isabs(args.out) else os.path.join(os.path.dirname(os.path.abspath(__file__)), args.out)
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_path = os.path.join(out_dir, "report_%s.html" % stamp)
    json_path = os.path.join(out_dir, "findings_%s.json" % stamp)
    csv_path = os.path.join(out_dir, "findings_%s.csv" % stamp)

    write_report(html_path, source, len(events), findings, events)
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2)
    cols = ["id", "time", "severity", "rule_id", "name", "tactic", "technique", "host", "eid", "evidence",
            "image", "parent", "cmd", "user", "dest"]
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(findings)

    print("\n" + C["cyan"] + "=== RESULTS ===" + C["end"])
    print("Events analysed : %d\nFindings        : %d" % (len(events), len(findings)))
    for s in SEV_ORDER:
        print("  %s%-9s%s %d" % (C[s], s, C["end"], sum(1 for f in findings if f["severity"] == s)))
    print("\nTop findings:")
    order = {s: i for i, s in enumerate(SEV_ORDER)}
    for f in sorted(findings, key=lambda f: (order[f["severity"]], f["time"]))[:12]:
        print("  %s[%-8s]%s %s  %-9s %s  (%s)" % (C[f["severity"]], f["severity"], C["end"], f["time"],
                                                f["technique"], f["name"], f["host"].split(".")[0]))
    print("\nReport : " + html_path + "\nJSON   : " + json_path + "\nCSV    : " + csv_path)
    if not args.no_open:
        try:
            os.startfile(html_path)  # Windows
        except AttributeError:
            import webbrowser
            webbrowser.open("file://" + html_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())