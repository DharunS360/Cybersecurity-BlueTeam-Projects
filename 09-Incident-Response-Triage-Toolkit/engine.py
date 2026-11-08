"""
engine.py - runs the full triage pipeline (collect -> enrich -> analyze).
Shared by the GUI and the command-line mode.
"""
import os
from datetime import datetime

import analysis as A
import collectors as C


class Cancelled(Exception):
    pass


def run_triage(opts, progress=lambda pct, msg: None, cancelled=lambda: False):
    def step(pct, msg):
        if cancelled():
            raise Cancelled()
        progress(pct, msg)

    started = datetime.now()
    admin = C.is_admin()

    step(2, "Collecting host information")
    meta = C.collect_meta(opts)
    warn = meta["Warnings"]
    if not admin:
        warn.append("Not running as Administrator: Security event log, Prefetch, Defender exclusions and some "
                    "process details are unavailable. Relaunch as Administrator for full coverage.")

    step(6, "Enumerating running processes and hashing images")
    procs = C.collect_processes()

    if opts.get("verify_sig", True):
        step(16, "Verifying Authenticode signatures of running binaries")
        C.verify_signatures(procs, "Path")

    step(30, "Mapping network connections to processes")
    net = C.collect_network(procs)

    step(36, "Collecting persistence mechanisms (registry, startup, services, tasks, WMI)")
    pers = C.collect_persistence()
    if opts.get("verify_sig", True):
        step(46, "Verifying persistence targets")
        C.verify_signatures(pers, "Target")
    for r in pers:
        r["TargetSHA256"] = C.sha256_file(r.get("Target", ""))

    step(54, "Collecting accounts, DNS cache, ARP, shares, Defender and firewall state")
    arts = C.collect_artifacts()
    dns = {}
    for a in arts:
        if a["Category"] == "DNS Cache" and "->" in a["Detail"]:
            dns[a["Detail"].split("->")[1].strip()] = a["Name"]
    for r in net:
        r["Hostname"] = dns.get(r["Remote"], "")

    step(62, "Scanning user-writable directories for recent files")
    files = C.collect_files(opts.get("days", 7), opts.get("hash_files", True))
    step(72, "Collecting Prefetch / Recent execution traces")
    traces, pf_ok = C.collect_execution_traces(opts.get("days", 7))
    if not pf_ok:
        warn.append("Prefetch folder not readable (requires Administrator).")
    if opts.get("verify_sig", True):
        step(76, "Verifying signatures of recently dropped executables")
        execs = [r for r in files if os.path.splitext(r["Name"])[1].lower() in (".exe", ".dll", ".scr", ".com", ".cpl")]
        C.verify_signatures(execs[:150], "Path")
    files.extend(traces)

    events = []
    if opts.get("events", True):
        step(80, "Querying Windows event logs (Security, System, PowerShell, Defender)")
        events = C.collect_events(opts.get("hours", 24), include_security=admin)
        if not admin:
            warn.append("Security log skipped (requires Administrator).")

    step(94, "Applying detection rules, building timeline and extracting IOCs")
    data = {"meta": meta, "processes": procs, "network": net, "persistence": pers,
            "events": events, "files": files, "artifacts": arts}
    A.analyze(data)

    finished = datetime.now()
    meta["CollectionEndLocal"] = finished.strftime(C.TS)
    meta["DurationSeconds"] = round((finished - started).total_seconds(), 1)
    progress(100, "Triage complete")
    return data
