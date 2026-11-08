"""
IR Triage Toolkit - Project 09 of the Cybersecurity Blue Team portfolio.

  python main.py                 -> launch the GUI analyst console
  python main.py --cli           -> headless triage + case export (scriptable / remote use)
"""
import argparse
import os
import sys


def main():
    ap = argparse.ArgumentParser(description="Live Windows incident-response triage toolkit")
    ap.add_argument("--cli", action="store_true", help="run without the GUI and export a case folder")
    ap.add_argument("--analyst", default="", help="analyst name recorded in the case")
    ap.add_argument("--hours", type=int, default=24, help="event-log look-back window in hours")
    ap.add_argument("--days", type=int, default=7, help="file / prefetch look-back window in days")
    ap.add_argument("--no-sig", action="store_true", help="skip Authenticode signature verification (faster)")
    ap.add_argument("--no-hash", action="store_true", help="skip hashing of recently dropped files")
    ap.add_argument("--no-events", action="store_true", help="skip event-log collection")
    ap.add_argument("--auto-shots", action="store_true",
                    help="GUI mode: run a triage, save README screenshots to docs/screenshots, then exit")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "cases"),
                    help="output folder for case exports")
    args = ap.parse_args()

    if os.name != "nt":
        print("This toolkit collects live Windows artifacts and must run on Windows.")
        return 1

    if args.cli:
        import engine
        import report
        opts = {"analyst": args.analyst, "hours": args.hours, "days": args.days, "verify_sig": not args.no_sig,
                "hash_files": not args.no_hash, "events": not args.no_events}
        data = engine.run_triage(opts, lambda p, m: print("[%3d%%] %s" % (p, m)))
        os.makedirs(args.out, exist_ok=True)
        case = report.export_case(data, args.out)
        s = data["summary"]
        print("\nRisk: %s (%d/100)  Critical=%d High=%d Medium=%d Low=%d  IOCs=%d" % (
            s["label"], s["score"], s["counts"]["Critical"], s["counts"]["High"], s["counts"]["Medium"],
            s["counts"]["Low"], len(data["iocs"])))
        for w in data["meta"]["Warnings"]:
            print("WARNING:", w)
        print("Case exported to:", case)
        return 0

    try:
        import gui
    except ImportError as e:
        print("Missing dependency (%s). Run:  pip install -r requirements.txt" % e)
        return 1
    gui.run_gui(auto=args.auto_shots)
    return 0


if __name__ == "__main__":
    sys.exit(main())
