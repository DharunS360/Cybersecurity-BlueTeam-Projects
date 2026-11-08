"""
analysis.py - detection rules, MITRE ATT&CK mapping, risk scoring, timeline and IOC extraction.
Operates only on artifacts collected from the live host by collectors.py.
"""
import ipaddress
import json
import os
import re
import urllib.error
import urllib.request
from collections import Counter, defaultdict

SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
SEV_SCORE = {"Critical": 90, "High": 70, "Medium": 45, "Low": 20, "Info": 5}
SYSROOT = os.environ.get("SystemRoot", r"C:\Windows").lower()
PF = (os.environ.get("ProgramFiles", r"C:\Program Files").lower(),
      os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)").lower())

MITRE = {
    "T1003": "OS Credential Dumping", "T1003.001": "LSASS Memory", "T1021.001": "Remote Desktop Protocol",
    "T1021.002": "SMB/Windows Admin Shares", "T1021.006": "Windows Remote Management",
    "T1027": "Obfuscated Files or Information", "T1036": "Masquerading",
    "T1036.005": "Match Legitimate Name or Location", "T1036.007": "Double File Extension",
    "T1047": "Windows Management Instrumentation", "T1048": "Exfiltration Over Alternative Protocol",
    "T1053.005": "Scheduled Task", "T1059": "Command and Scripting Interpreter", "T1059.001": "PowerShell",
    "T1070.001": "Clear Windows Event Logs", "T1071": "Application Layer Protocol",
    "T1078": "Valid Accounts", "T1087": "Account Discovery", "T1095": "Non-Application Layer Protocol",
    "T1098": "Account Manipulation", "T1105": "Ingress Tool Transfer", "T1110": "Brute Force",
    "T1136.001": "Create Account: Local Account", "T1140": "Deobfuscate/Decode Files or Information",
    "T1197": "BITS Jobs", "T1204.002": "User Execution: Malicious File", "T1218": "System Binary Proxy Execution",
    "T1218.005": "Mshta", "T1218.010": "Regsvr32", "T1218.011": "Rundll32", "T1219": "Remote Access Software",
    "T1490": "Inhibit System Recovery", "T1496": "Resource Hijacking", "T1505.003": "Web Shell",
    "T1543.003": "Windows Service", "T1546": "Event Triggered Execution", "T1546.003": "WMI Event Subscription",
    "T1546.010": "AppInit DLLs", "T1546.012": "Image File Execution Options Injection",
    "T1547.001": "Registry Run Keys / Startup Folder", "T1547.004": "Winlogon Helper DLL",
    "T1562.001": "Disable or Modify Tools", "T1562.004": "Disable or Modify System Firewall",
    "T1564.003": "Hidden Window", "T1565.001": "Stored Data Manipulation", "T1569.002": "Service Execution",
    "T1571": "Non-Standard Port", "T1572": "Protocol Tunneling", "T1588.002": "Obtain Capabilities: Tool",
}

SYS_BIN = {"svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe", "smss.exe", "wininit.exe",
           "spoolsv.exe", "taskhostw.exe", "dllhost.exe", "conhost.exe", "fontdrvhost.exe", "sihost.exe",
           "runtimebroker.exe", "searchindexer.exe", "audiodg.exe", "ctfmon.exe", "dwm.exe"}
EXPECT_PARENT = {"svchost.exe": "services.exe", "lsass.exe": "wininit.exe", "services.exe": "wininit.exe"}
OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "onenote.exe", "visio.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
          "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe", "wmic.exe"}
LOLBIN_NET = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
              "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe", "msbuild.exe", "installutil.exe"}
OFFENSIVE = {"mimikatz.exe", "lazagne.exe", "rubeus.exe", "sharphound.exe", "bloodhound.exe", "pwdump.exe",
             "wce.exe", "fgdump.exe", "gsecdump.exe", "cobaltstrike.exe", "beacon.exe", "meterpreter.exe",
             "nanodump.exe", "safetykatz.exe", "seatbelt.exe", "crackmapexec.exe", "covenant.exe", "sliver.exe"}
DUAL_USE = {"psexec.exe": "T1569.002", "psexec64.exe": "T1569.002", "psexesvc.exe": "T1569.002",
            "nc.exe": "T1095", "ncat.exe": "T1095", "netcat.exe": "T1095", "ngrok.exe": "T1572",
            "chisel.exe": "T1572", "plink.exe": "T1572", "rclone.exe": "T1048", "anydesk.exe": "T1219",
            "teamviewer.exe": "T1219", "rustdesk.exe": "T1219", "procdump.exe": "T1003.001",
            "procdump64.exe": "T1003.001", "adfind.exe": "T1087"}
SUSP_PORTS = {4444, 5555, 1337, 31337, 6667, 9001, 9030, 9050, 12345, 54321}
MINER_PORTS = {3333, 14444, 45700}

CMD_RULES = [
    (re.compile(r"(?i)(mimikatz|sekurlsa::|lsadump::|procdump\S*\s.*lsass|comsvcs(\.dll)?[, ]+#?minidump|"
                r"ntdsutil.*ifm|reg(\.exe)?\s+save\s+hklm\\(sam|security|system))"),
     "Critical", "Credential dumping command line", "T1003"),
    (re.compile(r"(?i)(vssadmin(\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|wbadmin\s+delete\s+(catalog|backup|systemstatebackup)|"
                r"bcdedit.*recoveryenabled\s+no|bcdedit.*bootstatuspolicy\s+ignoreallfailures)"),
     "Critical", "Recovery inhibition (shadow copy / backup deletion)", "T1490"),
    (re.compile(r"(?i)(powershell|pwsh)\S*\s.*\s-e(?:nc|ncodedcommand|c)?\s+[A-Za-z0-9+/=]{30,}"),
     "High", "Encoded PowerShell command", "T1059.001"),
    (re.compile(r"(?i)(downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient|start-bitstransfer|invoke-restmethod)"),
     "High", "PowerShell download cradle", "T1105"),
    (re.compile(r"(?i)\b(iex|invoke-expression)\b"), "Medium", "PowerShell in-memory expression execution", "T1059.001"),
    (re.compile(r"(?i)frombase64string"), "Medium", "Base64 decoding in script", "T1027"),
    (re.compile(r"(?i)(powershell|pwsh)\S*\s.*-w(?:indowstyle)?\s+h(?:idden)?"), "Medium", "Hidden PowerShell window", "T1564.003"),
    (re.compile(r"(?i)system\.net\.sockets\.tcpclient|\bnc(at)?(\.exe)?\s+.*-e\s+(cmd|powershell)"),
     "High", "Reverse shell pattern", "T1059.001"),
    (re.compile(r"(?i)certutil(\.exe)?[\"\s].*(-urlcache|-decode|-encode|-f\s+http)"), "High", "Certutil used for download/decode", "T1105"),
    (re.compile(r"(?i)bitsadmin(\.exe)?[\"\s].*(/transfer|/addfile)"), "High", "BITSAdmin transfer", "T1197"),
    (re.compile(r"(?i)mshta(\.exe)?[\"\s].*(https?:|vbscript:|javascript:|\.hta)"), "High", "Mshta executing remote/script content", "T1218.005"),
    (re.compile(r"(?i)regsvr32(\.exe)?[\"\s].*(/i:|scrobj|https?:)"), "High", "Regsvr32 proxy execution (Squiblydoo)", "T1218.010"),
    (re.compile(r"(?i)rundll32(\.exe)?[\"\s].*(javascript:|https?:|mshtml)"), "High", "Rundll32 proxy execution", "T1218.011"),
    (re.compile(r"(?i)wmic(\.exe)?[\"\s].*(process\s+call\s+create|/node:)"), "High", "WMIC remote/process creation", "T1047"),
    (re.compile(r"(?i)\bnet1?(\.exe)?\s+(user\s+\S+\s+\S+\s+/add|localgroup\s+administrators\s+\S+\s+/add)"),
     "High", "Local account creation / admin group add", "T1136.001"),
    (re.compile(r"(?i)\bpsexe(c|svc)(64)?(\.exe)?\b"), "Medium", "PsExec remote execution", "T1569.002"),
    (re.compile(r"(?i)(set-mppreference\s+.*-disable(realtimemonitoring|behaviormonitoring|ioavprotection)\s+\$?true|"
                r"add-mppreference\s+.*-exclusion(path|process|extension)|sc(\.exe)?\s+(stop|config)\s+windefend|"
                r"netsh\s+advfirewall\s+set\s+\w+\s+state\s+off)"),
     "High", "Security tooling tampering", "T1562.001"),
]

LOLBIN_RX = re.compile(r"(?i)\b(powershell|pwsh|cmd(\.exe)?\s+/c|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msbuild|installutil)\b")
DOUBLE_EXT = re.compile(r"(?i)\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|zip|rtf)\.(exe|scr|bat|cmd|com|js|vbs|hta|ps1)$")


# --------------------------------------------------------------------------- helpers
def n(p):
    return (p or "").lower().replace("/", "\\")


def user_writable(p):
    q = n(p)
    if not q:
        return False
    if "\\programdata\\" in q and "\\programdata\\microsoft\\" not in q:
        return True
    return any(d in q for d in ("\\appdata\\", "\\temp\\", "\\downloads\\", "\\users\\public\\",
                                "\\$recycle.bin\\", "\\perflogs\\", "\\desktop\\"))


def trusted_loc(p):
    q = n(p)
    return q.startswith(SYSROOT) or any(q.startswith(x) for x in PF)


def sig_state(r):
    s = r.get("Signature", "")
    if s == "Valid":
        return "valid"
    if s == "":
        return "unknown"
    if s == "HashMismatch":
        return "bad"
    return "none"


def writable_sev(state):
    return {"valid": "Low", "unknown": "Medium", "none": "High", "bad": "High"}[state]


def cmd_hits(cmd):
    return [(sev, title, mitre) for rx, sev, title, mitre in CMD_RULES if rx.search(cmd or "")]


def osa1(a, b):
    """True when Damerau/OSA edit distance between a and b is exactly 1."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            c = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + c)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb] == 1


def tag(row, sev, flag):
    if SEV_RANK[sev] > SEV_RANK.get(row.get("Severity", ""), -1):
        row["Severity"] = sev
    row["Flags"] = (row.get("Flags", "") + "; " if row.get("Flags") else "") + flag


# --------------------------------------------------------------------------- analyzers
def analyze_processes(rows, add):
    for r in rows:
        name, path = (r["Name"] or "").lower(), n(r["Path"])
        parent, cmd = (r["Parent"] or "").lower(), r["CmdLine"] or ""
        st = sig_state(r)
        ent = "%s (PID %s)" % (r["Name"], r["PID"])
        when = r["Started"]
        ctx = "Path: %s\nCmd: %s\nParent: %s\nUser: %s" % (r["Path"], cmd[:500], r["Parent"], r["User"])

        if name in OFFENSIVE:
            add("Critical", "Process", "Known offensive tool running: " + r["Name"], ctx, "T1588.002", ent, when, r)
        elif name in DUAL_USE:
            add("Medium", "Process", "Dual-use admin/attacker tool running: " + r["Name"], ctx, DUAL_USE[name], ent, when, r)

        if path and name in SYS_BIN:
            ok = path.startswith(SYSROOT + "\\system32\\") or path.startswith(SYSROOT + "\\syswow64\\")
            if not ok:
                add("Critical", "Process", "System process name running from wrong location (masquerading)",
                    ctx, "T1036.005", ent, when, r)
        if path and name == "explorer.exe" and path != SYSROOT + "\\explorer.exe":
            add("Critical", "Process", "explorer.exe running from wrong location (masquerading)", ctx, "T1036.005", ent, when, r)
        if name in EXPECT_PARENT and parent and parent != EXPECT_PARENT[name]:
            add("High", "Process", "%s has unexpected parent (%s)" % (r["Name"], r["Parent"]), ctx, "T1036", ent, when, r)
        if name not in SYS_BIN and len(name) >= 7 and any(osa1(name, s) for s in SYS_BIN | {"explorer.exe"}):
            add("High", "Process", "Look-alike of a Windows system process name", ctx, "T1036.005", ent, when, r)

        if parent in OFFICE and name in SHELLS:
            add("Critical", "Process", "Office application spawned a shell/script host", ctx, "T1204.002", ent, when, r)
        elif parent == "wmiprvse.exe" and name in ("powershell.exe", "cmd.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"):
            add("High", "Process", "WMI provider spawned a shell (remote WMI execution)", ctx, "T1047", ent, when, r)
        elif parent == "w3wp.exe" and name in ("cmd.exe", "powershell.exe", "pwsh.exe", "whoami.exe", "net.exe", "net1.exe"):
            add("High", "Process", "IIS worker spawned a shell (possible web shell)", ctx, "T1505.003", ent, when, r)
        elif parent in ("httpd.exe", "nginx.exe", "sqlservr.exe") and name in ("cmd.exe", "powershell.exe", "pwsh.exe"):
            add("Medium", "Process", "Server process spawned a shell", ctx, "T1505.003", ent, when, r)
        elif parent in ("mshta.exe", "wscript.exe", "cscript.exe") and name in ("powershell.exe", "cmd.exe"):
            add("Medium", "Process", "Script host spawned a shell", ctx, "T1059", ent, when, r)

        if path and user_writable(path):
            title = "Process running from a user-writable location" + (" (validly signed)" if st == "valid" else "")
            add(writable_sev(st), "Process", title, ctx, "T1036", ent, when, r)
        elif path and not trusted_loc(path) and st in ("none", "bad"):
            add("High" if st == "bad" else "Medium", "Process",
                "Binary with invalid signature" if st == "bad" else "Unsigned binary outside system/program directories",
                ctx, "T1036", ent, when, r)
        if st == "bad":
            add("High", "Process", "Signature hash mismatch (possible tampered binary)", ctx, "T1036", ent, when, r)

        for sev, title, mitre in cmd_hits(cmd):
            add(sev, "Process", title, ctx, mitre, ent, when, r)


def analyze_network(rows, add):
    for r in rows:
        pname = (r["Process"] or "").lower()
        ent = "%s:%s -> %s:%s (%s)" % (r["Local"], r["LPort"], r["Remote"], r["RPort"], r["Process"] or "PID %s" % r["PID"])
        ctx = "Process: %s (PID %s)\nPath: %s\nState: %s" % (r["Process"], r["PID"], r["Path"], r["State"])
        st = sig_state({"Signature": r.get("Signature", "")})
        if r["State"] == "ESTABLISHED" and r["Scope"] == "Public":
            if pname in LOLBIN_NET:
                add("High", "Network", "Script host / LOLBin with external connection: " + r["Process"], ctx, "T1071", ent, "", r)
            elif r["Path"] and user_writable(r["Path"]) and st != "valid":
                add("High", "Network", "Unsigned/unknown program in user directory talking to the internet", ctx, "T1071", ent, "", r)
            if r["RPort"] in SUSP_PORTS:
                add("Medium", "Network", "Connection to port associated with C2/backdoors/Tor (%s)" % r["RPort"], ctx, "T1571", ent, "", r)
            if r["RPort"] in MINER_PORTS:
                add("High", "Network", "Connection to common crypto-mining pool port (%s)" % r["RPort"], ctx, "T1496", ent, "", r)
            if r["RPort"] == 3389:
                add("High", "Network", "Outbound RDP to a public IP", ctx, "T1021.001", ent, "", r)
            if r["RPort"] in (445, 5985, 5986):
                add("High", "Network", "Outbound SMB/WinRM to a public IP", ctx, "T1021.002", ent, "", r)
        if r["State"] == "ESTABLISHED" and r["Scope"] == "Private" and r["RPort"] in (3389, 5985, 5986, 22, 23) and r["PID"] != 4:
            add("Low", "Network", "Lateral-movement capable protocol to internal host (port %s)" % r["RPort"], ctx, "T1021.001", ent, "", r)
        if r["State"] == "LISTEN" and r["Local"] in ("0.0.0.0", "::") and r["Path"] and user_writable(r["Path"]) and st != "valid":
            add("Medium", "Network", "User-directory program listening on all interfaces (port %s)" % r["LPort"], ctx, "T1571", ent, "", r)


def _persist_mitre(typ):
    return {"Registry Run Key": "T1547.001", "Startup Folder": "T1547.001", "Scheduled Task": "T1053.005",
            "Service": "T1543.003", "WMI Subscription": "T1546.003", "Winlogon": "T1547.004",
            "IFEO": "T1546.012", "AppInit": "T1546.010"}.get(typ, "T1546")


def analyze_persistence(rows, add):
    for r in rows:
        typ, val, tgt = r["Type"], r["Value"] or "", r.get("Target", "")
        st = sig_state(r)
        mit = _persist_mitre(typ)
        ent = "%s: %s" % (typ, r["Name"])
        ctx = "Location: %s\nValue: %s\nTarget: %s\nSignature: %s %s" % (
            r["Location"], val[:500], tgt, r.get("Signature", ""), r.get("Signer", ""))

        if typ == "WMI Subscription":
            add("Critical", "Persistence", "WMI event consumer present (fileless persistence)", ctx, mit, ent, "", r)
            continue
        if typ == "IFEO":
            add("High", "Persistence", "Image File Execution Options debugger set for " + r["Name"], ctx, mit, ent, "", r)
            continue
        if typ == "AppInit":
            add("High", "Persistence", "AppInit_DLLs configured", ctx, mit, ent, "", r)
            continue
        if typ == "Winlogon":
            v = val.lower().replace(" ", "")
            if r["Name"] == "Shell" and v != "explorer.exe":
                add("High", "Persistence", "Winlogon Shell modified: " + val, ctx, mit, ent, "", r)
            elif r["Name"] == "Userinit" and v.rstrip(",") != SYSROOT + "\\system32\\userinit.exe":
                add("High", "Persistence", "Winlogon Userinit modified: " + val, ctx, mit, ent, "", r)
            elif r["Name"] in ("Taskman", "VmApplet"):
                add("High", "Persistence", "Winlogon %s value present" % r["Name"], ctx, mit, ent, "", r)
            continue

        flagged = False
        for sev, title, m in cmd_hits(val):
            add(sev, "Persistence", title + " (in %s)" % typ.lower(), ctx, m, ent, "", r)
            flagged = True
        if tgt and user_writable(tgt):
            add(writable_sev(st), "Persistence", "%s launches binary from user-writable path" % typ + (" (signed)" if st == "valid" else ""),
                ctx, mit, ent, "", r)
            flagged = True
        elif LOLBIN_RX.search(val) and typ != "Service":
            add("Medium", "Persistence", "%s launches a script host / LOLBin" % typ, ctx, mit, ent, "", r)
            flagged = True
        elif typ == "Service" and LOLBIN_RX.search(val):
            add("High", "Persistence", "Service runs via script host / LOLBin (PsExec-style)", ctx, mit, ent, "", r)
            flagged = True
        if not flagged and tgt and not trusted_loc(tgt) and st in ("none", "bad"):
            add("High" if st == "bad" else "Medium", "Persistence",
                "%s target is unsigned and outside system/program directories" % typ, ctx, mit, ent, "", r)
            flagged = True
        if not flagged and typ == "Startup Folder":
            add("Low", "Persistence", "Item in Startup folder", ctx, mit, ent, r.get("Modified", ""), r)


def _kv(detail, key):
    m = re.search(key + r"=(\S*)", detail or "")
    return m.group(1) if m else ""


def analyze_events(rows, add):
    fails, succ = defaultdict(list), []
    for r in rows:
        eid, d, t, log = r.get("EventID"), r.get("Detail") or "", r.get("Time", ""), r.get("Log", "")
        ent = "EventID %s @ %s" % (eid, t)
        ctx = "Log: %s\nProvider: %s\n%s\n%s" % (log, r.get("Provider", ""), d, r.get("Message", ""))
        if eid == 1102 or (eid == 104 and log == "System"):
            add("Critical", "EventLog", "Windows event log was cleared", ctx, "T1070.001", ent, t, r)
        elif eid == 4625:
            key = _kv(d, "Src")
            key = key if key not in ("", "-") else "user:" + _kv(d, "User")
            fails[key].append(r)
        elif eid == 4624:
            src, lt, user = _kv(d, "Src"), _kv(d, "LogonType"), _kv(d, "User")
            succ.append((src, user, t))
            public = False
            try:
                public = bool(src) and ipaddress.ip_address(src).is_global
            except ValueError:
                pass
            if lt == "10" and public:
                add("High", "EventLog", "RDP logon from public IP %s (user %s)" % (src, user), ctx, "T1021.001", ent, t, r)
            elif lt == "3" and public:
                add("High", "EventLog", "Network logon from public IP %s (user %s)" % (src, user), ctx, "T1078", ent, t, r)
            elif lt == "10":
                add("Low", "EventLog", "RDP logon (user %s from %s)" % (user, src or "?"), ctx, "T1021.001", ent, t, r)
        elif eid == 4688:
            m = re.search(r"Proc=(.*?) Parent=(.*?) Cmd=(.*)$", d)
            for sev, title, mitre in cmd_hits(m.group(3) if m else d):
                add(sev, "EventLog", title + " (process-creation audit)", ctx, mitre, ent, t, r)
        elif eid in (4697, 7045):
            path = (re.search(r"Path=(.*?)(?: By=| Account=|$)", d) or [None, ""])[1]
            if user_writable(path) or LOLBIN_RX.search(path):
                add("High", "EventLog", "New service installed from suspicious path", ctx, "T1543.003", ent, t, r)
            else:
                add("Medium", "EventLog", "New service installed", ctx, "T1543.003", ent, t, r)
        elif eid == 4698:
            add("Medium", "EventLog", "Scheduled task created", ctx, "T1053.005", ent, t, r)
        elif eid == 4720:
            add("Medium", "EventLog", "Local user account created", ctx, "T1136.001", ent, t, r)
        elif eid in (4728, 4732, 4756):
            grp = _kv(d, "Group").lower()
            add("High" if "admin" in grp else "Medium", "EventLog", "Member added to security group (%s)" % _kv(d, "Group"),
                ctx, "T1098", ent, t, r)
        elif eid == 4104:
            add("High", "EventLog", "Suspicious PowerShell script block logged", ctx, "T1059.001", ent, t, r)
        elif eid in (1116, 1117):
            add("High", "EventLog", "Windows Defender detected / acted on malware", ctx, "T1204.002", ent, t, r)
        elif eid == 5001:
            add("High", "EventLog", "Defender real-time protection disabled", ctx, "T1562.001", ent, t, r)

    for key, lst in fails.items():
        first = min(x["Time"] for x in lst)
        won = [s for s in succ if (s[0] == key or "user:" + s[1] == key) and s[2] >= first]
        if len(lst) >= 5 and won:
            for x in lst:
                tag(x, "Critical", "Logon success after failures")
            add("Critical", "EventLog", "Successful logon after %d failed attempts from %s (possible password guessing success)" % (len(lst), key),
                "First failure: %s\nSuccess: %s" % (first, won[0][2]), "T1110", key, first)
        elif len(lst) >= 10:
            for x in lst:
                tag(x, "High", "Brute force")
            add("High", "EventLog", "Brute force: %d failed logons from %s" % (len(lst), key),
                "First failure: %s\nLast failure: %s" % (first, max(x["Time"] for x in lst)), "T1110", key, first)
        elif len(lst) >= 3:
            for x in lst:
                tag(x, "Low", "Repeated failed logons")


def analyze_artifacts(rows, add):
    for r in rows:
        cat, name, det = r["Category"], r["Name"], r["Detail"]
        ent = "%s: %s" % (cat, name)
        if cat == "Local User" and name.lower() == "guest" and "Enabled=True" in det:
            add("Medium", "Accounts", "Guest account is enabled", det, "T1078", ent, "", r)
        elif cat == "Local Administrator" and not name.lower().endswith("\\administrator"):
            add("Low", "Accounts", "Non-default local administrator: " + name, det, "T1078", ent, "", r)
        elif cat == "Hosts File":
            if not re.match(r"^(127\.0\.0\.1|::1|0\.0\.0\.0)\s+localhost\s*$", det):
                add("Medium", "Network", "Custom hosts-file entry: " + det, det, "T1565.001", ent, r.get("Time", ""), r)
        elif cat == "SMB Share" and name not in ("ADMIN$", "C$", "IPC$") and not re.match(r"^[A-Z]\$$", name):
            add("Low", "Network", "Non-default SMB share: " + name, det, "T1021.002", ent, "", r)
        elif cat == "Firewall Profile" and "Enabled=False" in det:
            add("Medium", "Defense Evasion", "Firewall profile disabled: " + name, det, "T1562.004", ent, "", r)
        elif cat == "Defender Exclusion":
            add("Medium", "Defense Evasion", "Defender exclusion (%s): %s" % (name, det), det, "T1562.001", ent, "", r)
        elif cat == "Defender" and ("AV enabled=False" in det or "Real-time=False" in det):
            add("High", "Defense Evasion", "Windows Defender protection is off", det, "T1562.001", ent, "", r)
        elif cat == "Remote Desktop" and "ENABLED" in det:
            add("Low", "Network", "Remote Desktop is enabled on this host", det, "T1021.001", ent, "", r)


def analyze_files(rows, add):
    for r in rows:
        name, path = r["Name"], r["Path"]
        ext = os.path.splitext(name)[1].lower()
        st = sig_state(r)
        ctx = "Path: %s\nCreated: %s\nModified: %s\nSHA256: %s\nSignature: %s" % (
            path, r["Created"], r["Modified"], r["SHA256"], r.get("Signature", ""))
        low = name.lower()
        if r["Kind"] == "Prefetch":
            if low.rsplit(".pf", 1)[0] in OFFENSIVE:
                add("High", "Execution", "Prefetch shows execution of offensive tool: " + name, ctx, "T1588.002", name, r["Modified"], r)
            elif low.rsplit(".pf", 1)[0] in DUAL_USE:
                add("Medium", "Execution", "Prefetch shows execution of dual-use tool: " + name, ctx, DUAL_USE[low.rsplit(".pf", 1)[0]], name, r["Modified"], r)
            continue
        if r["Kind"] != "Dropped File":
            continue
        if DOUBLE_EXT.search(name):
            add("High", "File", "Double-extension executable: " + name, ctx, "T1036.007", path, r["Modified"], r)
        elif ext in (".exe", ".dll", ".scr", ".com", ".cpl", ".msi"):
            sev = "High" if st == "bad" else ("Medium" if st in ("none", "unknown") else "Low")
            add(sev, "File", "Recent executable in user-writable location" + (" (unsigned)" if st == "none" else ""),
                ctx, "T1204.002", path, r["Modified"], r)
        elif ext in (".ps1", ".vbs", ".vbe", ".js", ".jse", ".hta", ".wsf", ".bat", ".cmd", ".jar"):
            add("Low", "File", "Recent script in user-writable location", ctx, "T1059", path, r["Modified"], r)
        elif ext in (".iso", ".img", ".docm", ".xlsm", ".pptm"):
            add("Low", "File", "Recent container/macro document", ctx, "T1204.002", path, r["Modified"], r)


# --------------------------------------------------------------------------- timeline
def build_timeline(data):
    tl = []

    def add(t, sev, src, ev, summ):
        if t:
            tl.append({"Time": t, "Severity": sev or "", "Source": src, "Event": ev, "Summary": (summ or "")[:300]})

    for r in data["processes"]:
        add(r["Started"], r["Severity"], "Process", "Process started",
            "%s (PID %s) <- %s | %s" % (r["Name"], r["PID"], r["Parent"] or "?", r["CmdLine"] or r["Path"]))
    for r in data["files"]:
        if r["Kind"] == "Prefetch":
            add(r["Modified"], r["Severity"], "Prefetch", "Program executed (last run)", r["Name"])
        elif r["Kind"] == "Recent LNK":
            add(r["Modified"], r["Severity"], "Recent", "File opened (LNK)", r["Name"])
        else:
            add(r["Created"], r["Severity"], "Filesystem", "File created/dropped", r["Path"])
            if r["Modified"] != r["Created"]:
                add(r["Modified"], r["Severity"], "Filesystem", "File modified", r["Path"])
    for r in data["events"]:
        add(r.get("Time"), r["Severity"], "EventLog", "%s / %s" % (r.get("Log", ""), r.get("EventID", "")),
            r.get("Detail") or r.get("Message"))
    for r in data["artifacts"]:
        if r.get("Time"):
            add(r["Time"], r["Severity"], "System", r["Category"], "%s - %s" % (r["Name"], r["Detail"]))
    for r in data["persistence"]:
        if r.get("Modified"):
            add(r["Modified"], r["Severity"], "Persistence", r["Type"], "%s -> %s" % (r["Name"], r["Value"]))
    tl.sort(key=lambda x: x["Time"], reverse=True)
    return tl


# --------------------------------------------------------------------------- IOC extraction
OCT = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
RX = {
    "IPv4": re.compile(r"(?<![\d.])(?:%s\.){3}%s(?![\d.])" % (OCT, OCT)),
    "URL": re.compile(r"https?://[^\s\"'<>)\]]+", re.I),
    "Domain": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|info|biz|ru|cn|xyz|top|tk|cc|pw|club|"
                         r"online|site|shop|live|dev|us|de|su|ly|gg|icu|cyou|ml|ga|cf|gq|buzz|click|link|work|rest|fun)\b", re.I),
    "Email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "SHA256": re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])"),
    "SHA1": re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])"),
    "MD5": re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])"),
}
BENIGN = ("microsoft.com", "windows.com", "windowsupdate.com", "live.com", "office.com", "office365.com", "msedge.net",
          "azure.com", "azureedge.net", "bing.com", "msn.com", "skype.com", "microsoftonline.com", "windows.net",
          "digicert.com", "verisign.com", "google.com", "googleapis.com", "gstatic.com", "mozilla.org", "mozilla.com",
          "mozilla.net", "apple.com", "w3.org", "schemas.microsoft.com", "xboxlive.com", "github.com")
IOC_TEXT_FIELDS = {"processes": ("CmdLine", "Path"), "persistence": ("Value", "Location"),
                   "events": ("Detail", "Message"), "files": ("Path",), "artifacts": ("Detail", "Name")}


def public_ip(s):
    try:
        return ipaddress.ip_address(s).is_global
    except ValueError:
        return False


def extract_iocs(data):
    bucket = {}

    def put(typ, val, ctx, sev, src):
        e = bucket.get((typ, val))
        if not e:
            e = bucket[(typ, val)] = {"Severity": sev, "Type": typ, "Value": val, "Count": 0,
                                      "Context": ctx[:200], "Sources": set(), "VT": ""}
        e["Count"] += 1
        e["Sources"].add(src)
        if SEV_RANK[sev] > SEV_RANK[e["Severity"]]:
            e["Severity"], e["Context"] = sev, ctx[:200]

    for sec, fields in IOC_TEXT_FIELDS.items():
        for r in data.get(sec, []):
            sev = r.get("Severity", "")
            if not sev:
                continue  # only mine rows that were flagged
            ctx = "%s | %s" % (r.get("Flags", ""), r.get("Name") or r.get("Path") or "")
            for f in fields:
                text = str(r.get(f, "") or "")
                for typ, rx in RX.items():
                    for m in rx.findall(text):
                        v = m if isinstance(m, str) else m[0]
                        if typ == "IPv4" and not public_ip(v):
                            continue
                        if typ == "Domain" and v.lower().endswith(BENIGN):
                            continue
                        put(typ, v.lower() if typ in ("Domain", "SHA256", "SHA1", "MD5", "Email") else v, ctx, sev, sec)
            if r.get("SHA256") and SEV_RANK[sev] >= 1:
                put("SHA256", r["SHA256"], ctx, sev, sec)
            if r.get("Path") and SEV_RANK[sev] >= 2 and user_writable(r["Path"]):
                put("File Path", r["Path"], ctx, sev, sec)
            if sec == "persistence" and r["Type"] == "Registry Run Key" and SEV_RANK[sev] >= 2:
                put("Registry Key", "%s\\%s" % (r["Location"], r["Name"]), ctx, sev, sec)
    for r in data.get("network", []):
        if r["Scope"] == "Public" and r["Remote"]:
            sev = r.get("Severity") or "Info"
            put("IPv4", r["Remote"], "%s -> %s:%s %s" % (r["Process"], r["Remote"], r["RPort"], r.get("Hostname", "")), sev, "network")
    out = list(bucket.values())
    for e in out:
        e["Sources"] = ", ".join(sorted(e["Sources"]))
    out.sort(key=lambda e: (-SEV_RANK[e["Severity"]], -e["Count"], e["Type"]))
    return out


def vt_lookup(ioc, api_key, timeout=20):
    """Query VirusTotal v3 for hash / IP / domain IOCs. Returns (text, malicious_count)."""
    ep = {"SHA256": "files", "SHA1": "files", "MD5": "files", "IPv4": "ip_addresses", "Domain": "domains"}.get(ioc["Type"])
    if not ep:
        return "n/a", 0
    req = urllib.request.Request("https://www.virustotal.com/api/v3/%s/%s" % (ep, ioc["Value"]),
                                 headers={"x-apikey": api_key, "accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            stats = json.load(resp)["data"]["attributes"]["last_analysis_stats"]
        mal, sus, tot = stats.get("malicious", 0), stats.get("suspicious", 0), sum(stats.values())
        return "%d/%d malicious%s" % (mal, tot, (", %d suspicious" % sus) if sus else ""), mal
    except urllib.error.HTTPError as e:
        return {404: "not found", 429: "rate limited", 401: "bad API key"}.get(e.code, "HTTP %d" % e.code), 0
    except Exception:
        return "error", 0


# --------------------------------------------------------------------------- orchestration
def risk_label(score):
    return "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "ELEVATED" if score >= 25 else "LOW"


def analyze(data):
    findings, seen = [], set()
    for sec in ("processes", "network", "persistence", "events", "files", "artifacts"):
        for r in data[sec]:
            r.setdefault("Severity", "")
            r.setdefault("Flags", "")

    def add(sev, cat, title, detail, mitre="", entity="", when="", row=None):
        if row is not None:
            tag(row, sev, title)
        key = (title, entity)
        if key in seen:
            return
        seen.add(key)
        findings.append({"Severity": sev, "Score": SEV_SCORE[sev], "Category": cat, "Title": title, "Entity": entity,
                         "MITRE": mitre, "Technique": MITRE.get(mitre, ""), "Time": when, "Detail": detail})

    analyze_processes(data["processes"], add)
    analyze_network(data["network"], add)
    analyze_persistence(data["persistence"], add)
    analyze_events(data["events"], add)
    analyze_artifacts(data["artifacts"], add)
    analyze_files(data["files"], add)

    findings.sort(key=lambda f: (-SEV_RANK[f["Severity"]], f["Title"]))
    c = Counter(f["Severity"] for f in findings)
    score = min(100, c["Critical"] * 30 + c["High"] * 12 + c["Medium"] * 4 + c["Low"])
    techs = Counter(f["MITRE"] for f in findings if f["MITRE"])
    data["findings"] = findings
    data["timeline"] = build_timeline(data)
    data["iocs"] = extract_iocs(data)
    data["summary"] = {
        "counts": {k: c.get(k, 0) for k in ("Critical", "High", "Medium", "Low", "Info")},
        "score": score, "label": risk_label(score),
        "top_mitre": [(t, MITRE.get(t, ""), k) for t, k in techs.most_common(10)],
    }
    return data
