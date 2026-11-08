"""Detection rule catalogue (MITRE ATT&CK mapped)."""
import base64
import ipaddress
import re

SEV_SCORE = {"Low": 25, "Medium": 50, "High": 75, "Critical": 100}
SEV_ORDER = ["Critical", "High", "Medium", "Low"]
TACTICS = ["Initial Access", "Execution", "Persistence", "Privilege Escalation",
           "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
           "Command and Control", "Impact"]

STATELESS = []


def rule(rid, name, tactic, technique, severity, desc):
    def deco(fn):
        STATELESS.append({"id": rid, "name": name, "tactic": tactic, "technique": technique,
                          "severity": severity, "description": desc, "fn": fn})
        return fn
    return deco


STATEFUL_META = [
    {"id": "HUNT-101", "name": "Brute force / password spraying", "tactic": "Credential Access",
     "technique": "T1110", "severity": "High",
     "description": "5+ failed logons (4625) from one source within 5 minutes."},
    {"id": "HUNT-102", "name": "Burst of discovery commands", "tactic": "Discovery",
     "technique": "T1087", "severity": "Medium",
     "description": "4+ distinct reconnaissance commands on one host within 5 minutes."},
    {"id": "HUNT-103", "name": "Multi-stage attack chain", "tactic": "Correlation",
     "technique": "N/A", "severity": "Critical",
     "description": "3+ distinct ATT&CK tactics observed on one host within 30 minutes."},
]


def base(path):
    return (path or "").lower().replace("/", "\\").split("\\")[-1]


def get(ev, key):
    return ev["data"].get(key, "") or ""


def pc(ev):
    """Return (image, cmdline, parent) for process-creation events (Sysmon 1 / Security 4688)."""
    d = ev["data"]
    if ev["eid"] == 1 and "sysmon" in ev["channel"].lower():
        return d.get("Image", "").lower(), d.get("CommandLine", "").lower(), d.get("ParentImage", "").lower()
    if ev["eid"] == 4688:
        return (d.get("NewProcessName", "").lower(), d.get("CommandLine", "").lower(),
                d.get("ParentProcessName", "").lower())
    return None


def is_sysmon(ev, eid):
    return ev["eid"] == eid and "sysmon" in ev["channel"].lower()


OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "onenote.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
          "rundll32.exe", "regsvr32.exe"}
NET_LOLBINS = {"powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
               "certutil.exe", "wscript.exe", "cscript.exe", "bitsadmin.exe", "msbuild.exe"}


@rule("HUNT-001", "Encoded PowerShell command", "Execution", "T1059.001", "High",
      "PowerShell launched with a Base64 encoded command; payload is decoded for the analyst.")
def r_encoded_ps(ev):
    p = pc(ev)
    if not p or base(p[0]) not in ("powershell.exe", "pwsh.exe"):
        return None
    m = re.search(r"\s-(?:e|ec|enc|encodedcommand)\s+([A-Za-z0-9+/=]{16,})", get(ev, "CommandLine"), re.I)
    if not m:
        return None
    b64 = m.group(1)
    try:
        decoded = base64.b64decode(b64 + "=" * (-len(b64) % 4)).decode("utf-16-le", "replace")
    except Exception:
        decoded = "(could not decode)"
    bad = re.search(r"downloadstring|iex|invoke-expression|frombase64|net\.webclient|bypass", decoded, re.I)
    return "Decoded payload: " + decoded[:300], ("Critical" if bad else "High")


@rule("HUNT-002", "Office application spawned a script interpreter", "Execution", "T1204.002", "Critical",
      "Word/Excel/Outlook starting cmd, PowerShell, mshta, wscript etc. (macro / phishing execution).")
def r_office_child(ev):
    p = pc(ev)
    if p and base(p[2]) in OFFICE and base(p[0]) in SHELLS:
        return "%s spawned %s" % (base(p[2]), base(p[0]))


@rule("HUNT-003", "Certutil used as downloader / decoder", "Command and Control", "T1105", "High",
      "certutil with -urlcache, -verifyctl or -decode (LOLBin ingress tool transfer).")
def r_certutil(ev):
    p = pc(ev)
    if p and base(p[0]) == "certutil.exe" and re.search(r"-urlcache|/urlcache|-verifyctl|-decode|-encode", p[1]):
        return "certutil LOLBin abuse"


@rule("HUNT-004", "Signed binary proxy execution", "Defense Evasion", "T1218", "High",
      "regsvr32 / mshta / rundll32 loading remote or script content.")
def r_proxy_exec(ev):
    p = pc(ev)
    if not p:
        return None
    img, cmd = base(p[0]), p[1]
    if img == "regsvr32.exe" and re.search(r"/i:\s*https?|scrobj\.dll", cmd):
        return "regsvr32 Squiblydoo pattern"
    if img == "mshta.exe" and re.search(r"https?:|vbscript|javascript", cmd):
        return "mshta executing remote/script content"
    if img == "rundll32.exe" and re.search(r"javascript:|mshtml,", cmd):
        return "rundll32 executing script content"


@rule("HUNT-005", "BITS job used for transfer", "Defense Evasion", "T1197", "Medium",
      "bitsadmin /transfer or /addfile.")
def r_bits(ev):
    p = pc(ev)
    if p and base(p[0]) == "bitsadmin.exe" and re.search(r"/transfer|/addfile", p[1]):
        return "bitsadmin transfer"


@rule("HUNT-006", "Credential dumping activity", "Credential Access", "T1003", "Critical",
      "Mimikatz keywords, comsvcs MiniDump, procdump on lsass, ntdsutil IFM, SAM/SYSTEM hive export.")
def r_cred_dump(ev):
    p = pc(ev)
    if not p:
        return None
    cmd = p[1]
    pats = [r"sekurlsa|mimikatz|lsadump|privilege::debug|kerberos::",
            r"comsvcs(\.dll)?\W+.*minidump",
            r"procdump.*lsass",
            r"ntdsutil.*(ifm|ntds)",
            r"reg(\.exe)?\s+save\s+hklm\\(sam|security|system)"]
    for pat in pats:
        if re.search(pat, cmd):
            return "Credential access pattern matched: " + pat


@rule("HUNT-007", "Recovery inhibition (shadow copy / backup deletion)", "Impact", "T1490", "Critical",
      "vssadmin/wmic shadow copy deletion, bcdedit recovery disabled, wbadmin delete (ransomware precursor).")
def r_inhibit(ev):
    p = pc(ev)
    if not p:
        return None
    img, cmd = base(p[0]), p[1]
    if img == "vssadmin.exe" and "delete" in cmd and "shadows" in cmd:
        return "vssadmin delete shadows"
    if img == "wmic.exe" and "shadowcopy" in cmd and "delete" in cmd:
        return "wmic shadowcopy delete"
    if img == "bcdedit.exe" and re.search(r"recoveryenabled\s+no|ignoreallfailures", cmd):
        return "bcdedit recovery disabled"
    if img == "wbadmin.exe" and re.search(r"delete\s+(catalog|backup|systemstatebackup)", cmd):
        return "wbadmin backup deletion"


@rule("HUNT-008", "Scheduled task created", "Persistence", "T1053.005", "Medium",
      "schtasks /create; escalated when task runs shells or user-writable binaries.")
def r_schtasks(ev):
    p = pc(ev)
    if p and base(p[0]) == "schtasks.exe" and "/create" in p[1]:
        if re.search(r"powershell|cmd(\.exe)?\s+/c|\\users\\public|\\temp\\|\\appdata\\|/ru\s+system|mshta|wscript", p[1]):
            return "Suspicious scheduled task", "High"
        return "Scheduled task created"


@rule("HUNT-009", "Registry autorun set via reg.exe", "Persistence", "T1547.001", "Medium",
      "reg add to Run/RunOnce, Winlogon or IFEO keys.")
def r_reg_run(ev):
    p = pc(ev)
    if p and base(p[0]) == "reg.exe" and " add " in p[1] and re.search(
            r"\\currentversion\\run|\\winlogon|image file execution options", p[1]):
        return "Autorun key modified by reg.exe"


@rule("HUNT-010", "Run key value written (Sysmon 13)", "Persistence", "T1547.001", "Medium",
      "Sysmon registry value set under a Run/RunOnce key.")
def r_runkey(ev):
    if is_sysmon(ev, 13) and "\\currentversion\\run" in get(ev, "TargetObject").lower():
        return "Run key: %s -> %s" % (get(ev, "TargetObject"), get(ev, "Details"))


@rule("HUNT-011", "Suspicious service installed", "Persistence", "T1543.003", "High",
      "Event 7045 / 4697 with shell, temp-path, UNC path or PsExec service binaries.")
def r_service(ev):
    if ev["eid"] not in (7045, 4697):
        return None
    path = get(ev, "ImagePath") or get(ev, "ServiceFileName")
    name = get(ev, "ServiceName")
    if re.search(r"cmd(\.exe)?\s+/c|powershell|\\temp\\|\\users\\|\\\\|psexesvc|%comspec%|mshta|rundll32", path.lower()):
        return "Service '%s' -> %s" % (name, path)


@rule("HUNT-012", "Local/domain account created", "Persistence", "T1136.001", "Medium",
      "Security event 4720.")
def r_acct(ev):
    if ev["eid"] == 4720:
        return "Account %s created by %s" % (get(ev, "TargetUserName"), get(ev, "SubjectUserName"))


@rule("HUNT-013", "Member added to privileged group", "Persistence", "T1098", "High",
      "Events 4728/4732/4756 targeting Administrators, Domain Admins and similar groups.")
def r_admin_add(ev):
    if ev["eid"] in (4728, 4732, 4756) and get(ev, "TargetUserName").lower() in (
            "administrators", "domain admins", "enterprise admins", "schema admins", "backup operators"):
        return "%s added a member to %s" % (get(ev, "SubjectUserName"), get(ev, "TargetUserName"))


@rule("HUNT-014", "Event log cleared", "Defense Evasion", "T1070.001", "Critical",
      "Security 1102 / System 104.")
def r_log_clear(ev):
    if ev["eid"] in (1102, 104):
        return "Audit log cleared by %s" % (get(ev, "SubjectUserName") or "unknown")


@rule("HUNT-015", "Execution from user-writable path", "Execution", "T1204.002", "Medium",
      "Executable launched from Public, ProgramData, Temp or Recycle Bin.")
def r_writable(ev):
    p = pc(ev)
    if not p or not p[0].endswith(".exe"):
        return None
    if "\\programdata\\microsoft\\" in p[0] or "\\programdata\\package cache\\" in p[0]:
        return None
    if re.search(r"\\users\\public\\|\\programdata\\|\\windows\\temp\\|\\appdata\\local\\temp\\|\\\$recycle\.bin\\", p[0]):
        return "Binary executed from " + p[0]


@rule("HUNT-016", "Remote execution tooling", "Lateral Movement", "T1021.002", "High",
      "PsExec/PAExec/WinRS, wmic /node or sc \\\\host.")
def r_remote_exec(ev):
    p = pc(ev)
    if not p:
        return None
    img, cmd = base(p[0]), p[1]
    if img in ("psexec.exe", "psexec64.exe", "paexec.exe", "winrs.exe"):
        return "%s remote execution" % img
    if img == "wmic.exe" and "/node:" in cmd:
        return "wmic remote execution"
    if re.search(r"\bsc(\.exe)?\s+\\\\", cmd):
        return "sc.exe remote service control"


TRUSTED_LSASS = {"msmpeng.exe", "svchost.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
                 "wmiprvse.exe", "taskmgr.exe", "vmtoolsd.exe", "mssense.exe", "senseir.exe"}
DUMP_MASKS = {"0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff", "0x1f0fff", "0x1f1fff", "0x1f2fff", "0x1f3fff"}


@rule("HUNT-017", "LSASS memory access", "Credential Access", "T1003.001", "Critical",
      "Sysmon 10 with dump-capable access mask from an untrusted process.")
def r_lsass(ev):
    if is_sysmon(ev, 10) and get(ev, "TargetImage").lower().endswith("\\lsass.exe"):
        if base(get(ev, "SourceImage")) not in TRUSTED_LSASS and get(ev, "GrantedAccess").lower() in DUMP_MASKS:
            return "%s opened lsass.exe with access %s" % (get(ev, "SourceImage"), get(ev, "GrantedAccess"))


@rule("HUNT-018", "Security tooling tampering", "Defense Evasion", "T1562.001", "High",
      "Defender preference changes, exclusions, service stop.")
def r_defender(ev):
    p = pc(ev)
    if p and re.search(r"(set|add)-mppreference.*(disablerealtimemonitoring|exclusionpath|exclusionprocess|exclusionextension)"
                       r"|sc(\.exe)?\s+(stop|config)\s+windefend|disableantispyware", p[1]):
        return "Defender tampering attempt"


@rule("HUNT-019", "Script/LOLBin initiated external connection", "Command and Control", "T1071.001", "Medium",
      "Sysmon 3 outbound connection from scripting engine or LOLBin to a public IP.")
def r_lolbin_net(ev):
    if not is_sysmon(ev, 3) or get(ev, "Initiated").lower() != "true":
        return None
    img = base(get(ev, "Image"))
    if img not in NET_LOLBINS:
        return None
    try:
        ip = ipaddress.ip_address(get(ev, "DestinationIp"))
    except ValueError:
        return None
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        return None
    return "%s connected to %s:%s" % (img, ip, get(ev, "DestinationPort"))


@rule("HUNT-020", "Possible pass-the-hash logon (heuristic)", "Lateral Movement", "T1550.002", "Medium",
      "Network logon (type 3) using NTLM with zero key length for a non-machine account.")
def r_pth(ev):
    if ev["eid"] == 4624 and get(ev, "LogonType") == "3" and get(ev, "AuthenticationPackageName").upper() == "NTLM" \
            and get(ev, "KeyLength") == "0":
        user = get(ev, "TargetUserName")
        if user and not user.endswith("$") and user.upper() not in ("ANONYMOUS LOGON", "-"):
            return "NTLM network logon for %s from %s" % (user, get(ev, "IpAddress") or get(ev, "WorkstationName"))


@rule("HUNT-021", "WMI event subscription persistence", "Persistence", "T1546.003", "High",
      "Sysmon 19/20/21 WMI filter, consumer or binding activity.")
def r_wmi(ev):
    if ev["eid"] in (19, 20, 21) and "sysmon" in ev["channel"].lower():
        return "WMI subscription: %s %s" % (get(ev, "Name"), get(ev, "Destination"))


@rule("HUNT-022", "Remote thread injection", "Defense Evasion", "T1055", "High",
      "Sysmon 8 CreateRemoteThread from an untrusted source process.")
def r_remote_thread(ev):
    if is_sysmon(ev, 8) and base(get(ev, "SourceImage")) not in (
            "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe"):
        return "%s injected into %s" % (get(ev, "SourceImage"), get(ev, "TargetImage"))


@rule("HUNT-023", "File dropped in Startup folder", "Persistence", "T1547.001", "Medium",
      "Sysmon 11 file creation in Start Menu Startup.")
def r_startup(ev):
    if is_sysmon(ev, 11) and "\\start menu\\programs\\startup\\" in get(ev, "TargetFilename").lower():
        return "Startup item: " + get(ev, "TargetFilename")


@rule("HUNT-024", "Kerberoasting indicator", "Credential Access", "T1558.003", "Medium",
      "Event 4769 using RC4 (0x17) for a non-machine service account.")
def r_kerberoast(ev):
    if ev["eid"] == 4769 and get(ev, "TicketEncryptionType").lower() == "0x17":
        svc = get(ev, "ServiceName")
        if svc and not svc.endswith("$") and svc.lower() != "krbtgt":
            return "RC4 service ticket requested for %s by %s" % (svc, get(ev, "TargetUserName"))


@rule("HUNT-025", "Suspicious PowerShell script block", "Execution", "T1059.001", "Medium",
      "Event 4104 containing download cradles, AMSI bypass or offensive tooling keywords.")
def r_scriptblock(ev):
    if ev["eid"] != 4104:
        return None
    sb = get(ev, "ScriptBlockText")
    low = sb.lower()
    if re.search(r"invoke-mimikatz|amsiutils|amsiinitfailed|sharphound|invoke-kerberoast", low):
        return "Offensive tooling in script block: " + sb[:200], "High"
    if re.search(r"downloadstring|downloadfile|frombase64string|invoke-expression|iex\s*\(|reflection\.assembly|virtualalloc", low):
        return "Script block: " + sb[:200]


def catalog():
    rows = [{k: r[k] for k in ("id", "name", "tactic", "technique", "severity", "description")} for r in STATELESS]
    return rows + STATEFUL_META