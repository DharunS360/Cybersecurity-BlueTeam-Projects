"""PhishScope - Phishing Email Analyzer (Blue Team Project 10).

GUI : python main.py [file.eml]
CLI : python main.py file.eml --cli [--json out.json] [--html out.html] [--ioc out.csv]
"""
import argparse
import sys


def run_cli(a):
    from core import engine, report
    R = engine.analyze(a.file, progress=lambda p, m: print(f"[{p:3d}%] {m}", file=sys.stderr))
    v = R["verdict"]
    print(f"\nVERDICT: {v['label']}  SCORE: {R['score']}/100")
    print(f"Subject: {R['meta']['subject']}\nFrom   : {R['meta']['from']}")
    au = R["auth"]
    print(f"SPF={au['spf']['effective']}  DKIM={au['dkim']['effective']}  DMARC={au['dmarc']['effective']}\n")
    for f in R["findings"]:
        print(f"[{f['sev'].upper():8}] +{f['points']:<3} {f['title']}  -- {f['detail'][:110]}")
    if a.json:
        report.to_json(R, a.json)
    if a.html:
        report.to_html(R, a.html)
    if a.ioc:
        report.iocs_csv(R, a.ioc)


def main():
    ap = argparse.ArgumentParser(description="PhishScope - phishing e-mail analyzer")
    ap.add_argument("file", nargs="?", help=".eml file")
    ap.add_argument("--cli", action="store_true")
    ap.add_argument("--json")
    ap.add_argument("--html")
    ap.add_argument("--ioc")
    a = ap.parse_args()
    if a.cli:
        if not a.file:
            ap.error("--cli needs a file")
        run_cli(a)
    else:
        from gui.app import run
        run(a.file)


if __name__ == "__main__":
    main()
