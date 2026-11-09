"""Extended detection pack - fills every MITRE ATT&CK tactic column."""
import ipaddress
import re

from .parser import LIVE_CHANNELS
from .rules import SHELLS, TACTICS, base, get, is_sysmon, pc, rule

TACTICS[:] = ["Initial Access", "Execution", "Persistence", "Privilege Escalation",
              "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
              "Collection", "Command and Control", "Exfiltration", "Impact", "Correlation"]

DEFENDER = "Microsoft-Windows-Windows Defender/Operational"
if DEFENDER not in LIVE_CHANNELS:
    LIVE_CHANNELS.append(DEFENDER)

_n = [25]


def _id():
    _n[0] += 1
    # HUNT-101..HUNT-103 are reserved for the three stateful engine rules.
    # Keep the stateless catalogue IDs unique for reports and investigations.
    if 101 <= _n[0] <= 103:
        _n[0] = 104
    return "HUNT-%03d" % _n[0]


def is_public(value):
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


USER_PATHS = r"(\\users\\|\\temp\\|\\programdata\\|\\appdata\\)"
BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "iexplore.exe"}


# ---------------------------------------------------------------- factories
def cmd_rule(name, tactic, tech, sev, desc, pattern, images=None):
    rx = re.compile(pattern, re.S)

    def fn(ev):
        p = pc(ev)
        if not p or (images and base(p[0]) not in images):
            return None
        m = rx.search(p[1])
        if m:
            return "%s -> %s" % (name, (m.group(0) or p[1])[:140])
    rule(_id(), name, tactic, tech, sev, desc)(fn)


def parent_rule(name, tactic, tech, sev, desc, parents, children):
    def fn(ev):
        p = pc(ev)
        if p and base(p[2]) in parents and base(p[0]) in children:
            return "%s spawned %s" % (base(p[2]), base(p[0]))
    rule(_id(), name, tactic, tech, sev, desc)(fn)


# ------------------------------------------------- command-line detections
CMD_RULES = [
    ("Firewall tampering", "Defense Evasion", "T1562.004", "Medium", "netsh/PowerShell firewall rule added or profile disabled.",
     r"netsh(\.exe)?\s+(advfirewall|firewall).*(add\s+rule|state\s+off|set\s+rule)|set-netfirewallprofile.*-enabled\s+false|new-netfirewallrule", None),
    ("Event log clearing via command", "Defense Evasion", "T1070.001", "High", "wevtutil cl / Clear-EventLog.",
     r"wevtutil(\.exe)?\s+(cl|clear-log)\s|clear-eventlog|remove-eventlog|limit-eventlog", None),
    ("Audit policy disabled", "Defense Evasion", "T1562.002", "High", "auditpol /clear or event channel disabled.",
     r"auditpol(\.exe)?\s+/(clear|remove)|wevtutil(\.exe)?\s+sl\s.*/e:false", None),
    ("PowerShell version downgrade", "Defense Evasion", "T1562.010", "High", "powershell -version 2 to dodge AMSI/logging.",
     r"-ver(sion)?\s+2(\.0)?\b", {"powershell.exe"}),
    ("PowerShell hidden/no-profile execution", "Execution", "T1059.001", "Medium", "-NoProfile combined with hidden window.",
     r"(?=.*-nop(rofile)?\b)(?=.*-w(indowstyle)?\s+h(idden)?\b)", {"powershell.exe", "pwsh.exe"}),
    ("AMSI / script logging bypass", "Defense Evasion", "T1562.001", "High", "AMSI reflection bypass or script block logging disabled.",
     r"amsiutils|amsiinitfailed|\[ref\]\.assembly\.gettype|scriptblocklogging.*(0|false)", None),
    ("PowerShell history tampering", "Defense Evasion", "T1070.003", "Medium", "Command history deleted or disabled.",
     r"consolehost_history|set-psreadlineoption.*savenothing|clear-history", None),
    ("Indirect command execution", "Defense Evasion", "T1202", "Medium", "forfiles/pcalua/scriptrunner used to launch commands.",
     r"forfiles(\.exe)?\s+.*/c\s+\W?(cmd|powershell)|pcalua(\.exe)?\s+-a|scriptrunner(\.exe)?\s+-appvscript|syncappvpublishingserver", None),
    ("Remote MSI installation", "Defense Evasion", "T1218.007", "High", "msiexec installing a package from a URL.",
     r"msiexec(\.exe)?\s+.*https?://", None),
    ("Script host running dropped script", "Execution", "T1059.005", "Medium", "wscript/cscript running scripts from user-writable paths.",
     USER_PATHS + r".*\.(js|jse|vbs|vbe|wsf)\b", {"wscript.exe", "cscript.exe"}),
    ("WMIC process creation", "Execution", "T1047", "High", "wmic process call create.",
     r"wmic(\.exe)?\s+.*process\s+call\s+create", None),
    ("DCOM lateral movement", "Lateral Movement", "T1021.003", "High", "MMC20/ShellWindows DCOM object abuse.",
     r"mmc20\.application|shellwindows|shellbrowserwindow|gettypefromprogid", None),
    ("WinRM / PowerShell remoting", "Lateral Movement", "T1021.006", "Medium", "Remoting enabled or used against other hosts.",
     r"enable-psremoting|winrm(\.cmd)?\s+quickconfig|invoke-command\s+.*-computername|enter-pssession|new-pssession", None),
    ("Remote scheduled task", "Lateral Movement", "T1053.005", "High", "schtasks /s targeting another host.",
     r"(?=.*\s/s\s+\S)(?=.*/(create|run)\b)", {"schtasks.exe"}),
    ("SMB exec via loopback admin share", "Lateral Movement", "T1021.002", "Critical", "smbexec/atexec style \\\\127.0.0.1\\ADMIN$ usage.",
     r"\\\\127\.0\.0\.1\\(admin|c)\$", None),
    ("RDP enabled / port forwarding", "Lateral Movement", "T1021.001", "High", "RDP switched on or netsh portproxy configured.",
     r"fdenytsconnections.*(/d\s+0|0x0)|remote desktop.*enable=yes|netsh.*portproxy|enable-netfirewallrule.*remote", None),
    ("Offensive remote-exec frameworks", "Lateral Movement", "T1021.002", "High", "Impacket / CrackMapExec / NetExec usage.",
     r"secretsdump|wmiexec|smbexec|atexec|psexec\.py|ntlmrelayx|crackmapexec|netexec", None),
    ("Kerberos attack tooling", "Credential Access", "T1558.003", "High", "Rubeus / Invoke-Kerberoast / ticket injection.",
     r"rubeus|invoke-kerberoast|\basktgt\b|\basktgs\b|kerberos::ptt|\bgetuserspns\b", None),
    ("Credential hunting in files/stores", "Credential Access", "T1552.001", "Medium", "findstr password, cmdkey /list, vaultcmd.",
     r"findstr(\.exe)?\s+.*password|cmdkey(\.exe)?\s+/list|vaultcmd(\.exe)?\s+/list|reg(\.exe)?\s+query.*/f\s+password|dir\s+/s.*pass", None),
    ("NTDS / SAM theft via shadow copy", "Credential Access", "T1003.003", "Critical", "ntds.dit access, shadow copy path, esentutl /vss.",
     r"ntds\.dit|globalroot\\device\\harddiskvolumeshadowcopy|esentutl(\.exe)?\s+.*(/y|/vss)", None),
    ("Named-pipe impersonation (getsystem)", "Privilege Escalation", "T1134.001", "High", "echo > \\\\.\\pipe\\ pattern used by getsystem.",
     r"echo\s.*>\s*\\\\\.\\pipe\\", None),
    ("UAC bypass registry hijack (command)", "Privilege Escalation", "T1548.002", "High", "ms-settings/mscfile/windir hijack via command line.",
     r"(ms-settings|mscfile|exefile)\\shell\\open\\command|\\environment.*\s/v\s+windir", None),
    ("Service binary path modified", "Privilege Escalation", "T1574.011", "Medium", "sc config ... binpath=.",
     r"\bsc(\.exe)?\s+(\\\\\S+\s+)?config\s+\S+\s+binpath", None),
    ("Sticky-keys / IFEO debugger backdoor", "Persistence", "T1546.008", "High", "Accessibility binary replaced or IFEO debugger set.",
     r"image file execution options.*debugger|(sethc|utilman|osk|magnify|narrator)\.exe.*(cmd|powershell)|copy.*cmd\.exe.*(sethc|utilman|osk|magnify)", None),
    ("Local account / admin added via command", "Persistence", "T1136.001", "High", "net user /add, localgroup administrators /add.",
     r"net1?\s+user\s+\S+\s+\S*\s*/add|net1?\s+localgroup\s+administrators\s+\S+\s+/add|new-localuser|add-localgroupmember.*administrators", None),
    ("Active Directory enumeration", "Discovery", "T1087.002", "Medium", "AdFind, SharpHound, dsquery, nltest trusts, domain admin queries.",
     r"\badfind\b|sharphound|bloodhound|\bdsquery\b|csvde|ldifde|nltest.*(domain_trusts|dclist|trusted_domains)|setspn(\.exe)?\s+-(q|t)|get-ad(user|computer|group|domain)|get-domain(user|computer|group|controller)|net1?\s+group\s+\W?(domain|enterprise) admins", None),
    ("Network / share discovery", "Discovery", "T1135", "Low", "net view, net share, arp -a, route print.",
     r"net1?\s+(view|share|session)|arp(\.exe)?\s+-a|nbtstat|route(\.exe)?\s+print|nslookup.*-type=(any|srv)", None),
    ("System / security software discovery", "Discovery", "T1082", "Low", "systeminfo, AV product queries, installed software.",
     r"systeminfo|wmic(\.exe)?\s+(product|qfe)|securitycenter2|antivirusproduct|get-mppreference|driverquery|reg(\.exe)?\s+query.*\\uninstall", None),
    ("Archive staging for collection", "Collection", "T1560.001", "Medium", "7z/rar with password or Compress-Archive.",
     r"\b(7z|7za|7zg|rar|winrar)(\.exe)?\W?\s+a\s.*-h?p\S*|compress-archive", None),
    ("Email collection (PST/OST)", "Collection", "T1114.001", "Medium", "Mailbox files copied or exported.",
     r"\.(pst|ost)\b.*(copy|xcopy|robocopy|compress|7z|move)|(copy|xcopy|robocopy)\s.*\.(pst|ost)\b|new-mailboxexportrequest", None),
    ("Ingress tool transfer via script/CLI", "Command and Control", "T1105", "Medium", "iwr/curl/wget/BITS downloading to disk.",
     r"(invoke-webrequest|iwr|invoke-restmethod|irm|wget|curl)(\.exe)?\s.*https?://.*(-outfile|\s-o\s|--output|>)|start-bitstransfer.*https?://", None),
    ("Remote access tool executed", "Command and Control", "T1219", "Medium", "AnyDesk, TeamViewer, ScreenConnect, RustDesk and similar.",
     r"", {"anydesk.exe", "teamviewer.exe", "screenconnect.clientservice.exe", "rustdesk.exe", "ultraviewer.exe",
           "ammyy.exe", "splashtop.exe", "atera.exe", "meshagent.exe"}),
    ("Tunnelling tool executed", "Command and Control", "T1572", "High", "ngrok, chisel, plink, frp, cloudflared.",
     r"", {"ngrok.exe", "chisel.exe", "plink.exe", "frpc.exe", "cloudflared.exe", "ligolo.exe"}),
    ("Cloud exfiltration tooling", "Exfiltration", "T1567.002", "High", "rclone, MEGAcmd, curl upload, pscp.",
     r"\brclone(\.exe)?\s+(copy|sync|move)|megacmd|megasync|\bcurl(\.exe)?\s.*(--upload-file|\s-t\s)|invoke-webrequest.*-method\s+post.*-infile|\bpscp(\.exe)?\s", None),
    ("Backup / database service stop", "Impact", "T1489", "High", "Ransomware-style stopping of SQL, backup and AV services.",
     r"(net1?\s+stop|sc(\.exe)?\s+(stop|config))\s+\W?(mssql|sql|veeam|backup|vss|sophos|msexchange|oracle|mysql|wsearch|windefend|sense|mbam)|taskkill(\.exe)?\s+.*/im\s+(sql|oracle|veeam|backup|msexchange|mysql|vmware)", None),
    ("Disk wipe / secure delete", "Impact", "T1485", "High", "cipher /w, sdelete, diskpart clean all, format.",
     r"cipher(\.exe)?\s+/w|\bsdelete(64)?(\.exe)?\s|diskpart.*clean all|format(\.com)?\s+\w:\s+/(fs|p)", None),
    ("Forced shutdown / reboot", "Impact", "T1529", "Medium", "shutdown /s or /r with /f.",
     r"shutdown(\.exe)?\s+.*/(s|r)\b.*/f|shutdown(\.exe)?\s+.*/f\b.*/(s|r)\b", None),
    ("Cryptominer indicators", "Impact", "T1496", "High", "xmrig, stratum pools, donate-level flags.",
     r"xmrig|stratum\+tcp|--donate-level|minerd|cpuminer|nicehash", None),
]
for _r in CMD_RULES:
    cmd_rule(*_r)

# ------------------------------------------------ parent/child detections
CHILD = SHELLS | {"whoami.exe", "net.exe", "net1.exe", "certutil.exe", "bitsadmin.exe", "systeminfo.exe",
                  "ipconfig.exe", "tasklist.exe"}
parent_rule("Web server / database spawned a shell", "Initial Access", "T1190", "Critical",
            "w3wp/httpd/nginx/tomcat/sqlservr launching shells or recon tools (web shell, ProxyShell, xp_cmdshell).",
            {"w3wp.exe", "httpd.exe", "nginx.exe", "php-cgi.exe", "tomcat9.exe", "tomcat8.exe", "sqlservr.exe"}, CHILD)
parent_rule("Document reader spawned a shell", "Execution", "T1203", "High",
            "PDF reader exploitation.", {"acrord32.exe", "acrobat.exe", "foxitreader.exe", "foxitpdfreader.exe"}, SHELLS)
parent_rule("UAC bypass via auto-elevated binary", "Privilege Escalation", "T1548.002", "High",
            "fodhelper/eventvwr/sdclt spawning a shell.",
            {"fodhelper.exe", "eventvwr.exe", "computerdefaults.exe", "sdclt.exe", "slui.exe"}, SHELLS)
parent_rule("Print spooler spawned a shell", "Privilege Escalation", "T1068", "Critical",
            "PrintNightmare style exploitation.", {"spoolsv.exe"}, SHELLS)
parent_rule("WMI provider spawned a shell", "Execution", "T1047", "High",
            "WmiPrvSE launching shells (remote WMI execution).", {"wmiprvse.exe"}, SHELLS)
parent_rule("WinRM host spawned a shell", "Lateral Movement", "T1021.006", "High",
            "wsmprovhost/winrshost launching shells (remote PowerShell).", {"wsmprovhost.exe", "winrshost.exe"}, SHELLS)


# ---------------------------------------------------- Initial Access (events)
@rule(_id(), "Remote logon from public IP", "Initial Access", "T1078", "High",
      "Network (3) or RDP (10) logon originating from a public IP address.")
def r_public_logon(ev):
    if ev["eid"] == 4624 and get(ev, "LogonType") in ("3", "10") and is_public(get(ev, "IpAddress")):
        user = get(ev, "TargetUserName")
        if user and user.upper() not in ("ANONYMOUS LOGON", "-"):
            return "%s logon type %s from public IP %s" % (user, get(ev, "LogonType"), get(ev, "IpAddress"))


@rule(_id(), "Risky attachment/download written to disk", "Initial Access", "T1566.001", "Medium",
      "Mail client or browser dropping ISO/LNK/HTA/macro files.")
def r_delivery(ev):
    if is_sysmon(ev, 11) and base(get(ev, "Image")) in (BROWSERS | {"outlook.exe", "olk.exe", "thunderbird.exe", "teams.exe"}):
        f = get(ev, "TargetFilename").lower()
        if f.endswith((".iso", ".img", ".hta", ".vbs", ".js", ".jse", ".wsf", ".lnk", ".docm", ".xlsm", ".pptm", ".one", ".chm", ".scr")):
            return "%s wrote %s" % (base(get(ev, "Image")), get(ev, "TargetFilename"))


@rule(_id(), "Removable media autorun file", "Initial Access", "T1091", "Medium", "autorun.inf created.")
def r_autorun(ev):
    if is_sysmon(ev, 11) and get(ev, "TargetFilename").lower().endswith("\\autorun.inf"):
        return "autorun.inf written: " + get(ev, "TargetFilename")


@rule(_id(), "Guest account enabled", "Initial Access", "T1078.001", "Medium", "Event 4722 enabling the Guest account.")
def r_guest(ev):
    if ev["eid"] == 4722 and get(ev, "TargetUserName").lower() == "guest":
        return "Guest account enabled by " + get(ev, "SubjectUserName")


# --------------------------------------------------------------- Execution
@rule(_id(), "Defender detected malware", "Execution", "T1204.002", "High", "Defender events 1116/1117.")
def r_def_detect(ev):
    if "defender" in ev["channel"].lower() and ev["eid"] in (1116, 1117):
        return "Threat %s at %s" % (get(ev, "Threat Name") or get(ev, "ThreatName"), get(ev, "Path"))


INPUT_RX = re.compile(r"get-clipboard|getasynckeystate|get-keystrokes|get-timedscreenshot|copyfromscreen|out-minidump|forms\.clipboard")


@rule(_id(), "Input / screen capture capability", "Collection", "T1056.001", "High",
      "Keylogging, clipboard or screenshot APIs in PowerShell.")
def r_input_capture(ev):
    text = get(ev, "ScriptBlockText").lower() if ev["eid"] == 4104 else (pc(ev) or ("", "", ""))[1]
    m = INPUT_RX.search(text)
    if m:
        return "Capture capability: " + m.group(0)


# ------------------------------------------------------------- Persistence
@rule(_id(), "Suspicious scheduled task registered (4698)", "Persistence", "T1053.005", "High",
      "Task XML launching shells, URLs or user-writable binaries.")
def r_task_event(ev):
    if ev["eid"] == 4698 and re.search(r"powershell|cmd(\.exe)?\s+/c|\\users\\public|\\temp\\|https?://|mshta|wscript|rundll32",
                                       get(ev, "TaskContent").lower()):
        return "Task %s by %s" % (get(ev, "TaskName"), get(ev, "SubjectUserName"))


# ---------------------------------------------------- Privilege Escalation
@rule(_id(), "UAC bypass registry hijack (Sysmon 13)", "Privilege Escalation", "T1548.002", "High",
      "COM/ms-settings handler hijack used by fodhelper/eventvwr bypasses.")
def r_uac_reg(ev):
    if is_sysmon(ev, 13) and re.search(r"\\(ms-settings|mscfile|exefile)\\shell\\open\\command|\\environment\\windir",
                                       get(ev, "TargetObject").lower()):
        return "Hijacked handler: " + get(ev, "TargetObject")


SAFE_DEBUG = {"svchost.exe", "lsass.exe", "services.exe", "wininit.exe", "csrss.exe", "taskmgr.exe", "msmpeng.exe",
              "vmtoolsd.exe", "procexp64.exe", "devenv.exe", "winlogon.exe"}


@rule(_id(), "SeDebugPrivilege enabled by unusual process", "Privilege Escalation", "T1134", "Medium",
      "Event 4703 enabling SeDebugPrivilege (token abuse prerequisite).")
def r_sedebug(ev):
    if ev["eid"] == 4703 and "sedebugprivilege" in get(ev, "EnabledPrivilegeList").lower() \
            and base(get(ev, "ProcessName")) not in SAFE_DEBUG:
        return "%s enabled SeDebugPrivilege" % get(ev, "ProcessName")


@rule(_id(), "Unsigned DLL loaded from writable path", "Privilege Escalation", "T1574.002", "Medium",
      "Sysmon 7 DLL side-loading indicator.")
def r_sideload(ev):
    if is_sysmon(ev, 7) and get(ev, "Signed").lower() == "false" and re.search(
            r"\\users\\public\\|\\programdata\\|\\windows\\temp\\|\\appdata\\local\\temp\\", get(ev, "ImageLoaded").lower()):
        return "%s loaded %s" % (base(get(ev, "Image")), get(ev, "ImageLoaded"))


BAD_DRIVERS = {"rtcore64.sys", "dbutil_2_3.sys", "gdrv.sys", "cpuz141.sys", "winring0x64.sys", "iqvw64e.sys", "kprocesshacker.sys"}


@rule(_id(), "Vulnerable or unsigned driver loaded (BYOVD)", "Privilege Escalation", "T1068", "High",
      "Sysmon 6 known-abused driver or unsigned driver.")
def r_driver(ev):
    if is_sysmon(ev, 6):
        name = base(get(ev, "ImageLoaded"))
        if name in BAD_DRIVERS:
            return "Known vulnerable driver loaded: " + name
        if get(ev, "Signed").lower() == "false":
            return "Unsigned driver loaded: " + name, "Medium"


@rule(_id(), "Print spooler dropped driver DLL", "Privilege Escalation", "T1068", "High",
      "spoolsv writing DLLs into the printer driver directory (PrintNightmare).")
def r_spooler_dll(ev):
    if is_sysmon(ev, 11) and base(get(ev, "Image")) == "spoolsv.exe" and "\\spool\\drivers\\x64\\3\\" in get(ev, "TargetFilename").lower() \
            and get(ev, "TargetFilename").lower().endswith(".dll"):
        return "Spooler wrote " + get(ev, "TargetFilename")


# ----------------------------------------------------------- Defense Evasion
TRUSTED_TIMESTOMP = {"onedrive.exe", "msiexec.exe", "svchost.exe", "teams.exe", "chrome.exe", "msedge.exe", "explorer.exe", "setup.exe"}


@rule(_id(), "File creation time changed (timestomping)", "Defense Evasion", "T1070.006", "Medium", "Sysmon 2 from an untrusted process.")
def r_timestomp(ev):
    if is_sysmon(ev, 2) and base(get(ev, "Image")) not in TRUSTED_TIMESTOMP:
        return "%s altered timestamps of %s" % (base(get(ev, "Image")), get(ev, "TargetFilename"))


@rule(_id(), "Process tampering / hollowing", "Defense Evasion", "T1055.012", "High", "Sysmon 25 image replaced or locked.")
def r_tamper(ev):
    if is_sysmon(ev, 25):
        return "%s: %s" % (get(ev, "Type") or "tampering", get(ev, "Image"))


SYSTEM_BINS = {"svchost.exe": "c:\\windows\\system32\\", "lsass.exe": "c:\\windows\\system32\\", "csrss.exe": "c:\\windows\\system32\\",
               "services.exe": "c:\\windows\\system32\\", "winlogon.exe": "c:\\windows\\system32\\", "smss.exe": "c:\\windows\\system32\\",
               "wininit.exe": "c:\\windows\\system32\\", "spoolsv.exe": "c:\\windows\\system32\\", "explorer.exe": "c:\\windows\\"}


@rule(_id(), "System binary name running from wrong path", "Defense Evasion", "T1036.005", "High",
      "svchost/lsass/explorer etc. executing outside their legitimate directory.")
def r_masquerade(ev):
    p = pc(ev)
    if p and p[0] and base(p[0]) in SYSTEM_BINS and not p[0].startswith(SYSTEM_BINS[base(p[0])]):
        return "%s executed from %s" % (base(p[0]), p[0])


@rule(_id(), "Obfuscated command line", "Defense Evasion", "T1027", "High",
      "Heavy backtick, [char], string concatenation or caret obfuscation.")
def r_obfuscation(ev):
    p = pc(ev)
    if not p:
        return None
    cmd = p[1]
    if cmd.count("`") >= 4 or len(re.findall(r"\[char\]\s*\d+", cmd)) >= 4 or len(re.findall(r"'\s*\+\s*'", cmd)) >= 5 \
            or (base(p[0]) == "cmd.exe" and cmd.count("^") >= 6):
        return "Obfuscation markers in command line: " + cmd[:120]


PROXY = {"installutil.exe": r"/logfile=.*\s/u\b|/u\b.*/logfile=", "regasm.exe": USER_PATHS + r".*\.dll",
         "regsvcs.exe": USER_PATHS + r".*\.dll", "cmstp.exe": r"/s.*\.inf|\.inf.*/s", "odbcconf.exe": r"[-/]a\s*\{?regsvr",
         "msbuild.exe": USER_PATHS + r".*\.(xml|csproj|proj|targets)", "msxsl.exe": r"https?://|\.xsl", "ieexec.exe": r"https?://"}


@rule(_id(), "Trusted developer utility proxy execution", "Defense Evasion", "T1127.001", "High",
      "InstallUtil/RegAsm/CMSTP/MSBuild/odbcconf running attacker payloads.")
def r_proxy_dev(ev):
    p = pc(ev)
    if p and base(p[0]) in PROXY and re.search(PROXY[base(p[0])], p[1]):
        return "%s abused with: %s" % (base(p[0]), p[1][:120])


@rule(_id(), "Defender real-time protection disabled", "Defense Evasion", "T1562.001", "Critical", "Defender events 5001/5010/5012.")
def r_def_off(ev):
    if "defender" in ev["channel"].lower() and ev["eid"] in (5001, 5010, 5012):
        return "Defender protection disabled (event %d)" % ev["eid"]


@rule(_id(), "Defender exclusion added", "Defense Evasion", "T1562.001", "High", "Defender event 5007 touching Exclusions.")
def r_def_excl(ev):
    if "defender" in ev["channel"].lower() and ev["eid"] == 5007 and "exclusions" in str(ev["data"]).lower():
        return "Exclusion change: " + (get(ev, "New Value") or get(ev, "NewValue"))[:140]


# --------------------------------------------------------- Credential Access
@rule(_id(), "DCSync replication request", "Credential Access", "T1003.006", "Critical",
      "Event 4662 using directory replication GUIDs by a non-machine account.")
def r_dcsync(ev):
    props = get(ev, "Properties").lower()
    if ev["eid"] == 4662 and not get(ev, "SubjectUserName").endswith("$") and re.search(
            r"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c", props):
        return "%s requested directory replication" % get(ev, "SubjectUserName")


@rule(_id(), "AS-REP roasting indicator", "Credential Access", "T1558.004", "Medium", "4768 without Kerberos pre-authentication.")
def r_asrep(ev):
    if ev["eid"] == 4768 and get(ev, "PreAuthType") in ("0", "0x0") and not get(ev, "TargetUserName").endswith("$"):
        return "TGT without pre-auth for " + get(ev, "TargetUserName")


@rule(_id(), "WDigest cleartext credential caching enabled", "Credential Access", "T1003.001", "High",
      "UseLogonCredential set to 1.")
def r_wdigest(ev):
    if is_sysmon(ev, 13) and "wdigest\\uselogoncredential" in get(ev, "TargetObject").lower() and "0x00000001" in get(ev, "Details").lower():
        return "WDigest UseLogonCredential enabled"


# ----------------------------------------------------------- Lateral Movement
@rule(_id(), "Admin share file write / service pipe access", "Lateral Movement", "T1021.002", "High",
      "Events 5145: executable written to ADMIN$/C$ or svcctl/atsvc pipe opened.")
def r_adminshare(ev):
    if ev["eid"] in (5140, 5145):
        share, rel = get(ev, "ShareName").lower(), get(ev, "RelativeTargetName").lower()
        if share.endswith(("\\admin$", "\\c$")) and rel.endswith((".exe", ".dll", ".bat", ".ps1", ".cmd", ".vbs")):
            return "%s written to %s" % (rel, share)
        if share.endswith("\\ipc$") and rel in ("svcctl", "atsvc"):
            return "Remote service control pipe '%s' opened from %s" % (rel, get(ev, "IpAddress"))


@rule(_id(), "NewCredentials logon (pass-the-hash / runas netonly)", "Lateral Movement", "T1550.002", "Medium",
      "Logon type 9 via seclogo.")
def r_type9(ev):
    if ev["eid"] == 4624 and get(ev, "LogonType") == "9" and get(ev, "LogonProcessName").lower().startswith("seclogo"):
        return "Type 9 logon by " + get(ev, "TargetUserName")


@rule(_id(), "Netlogon secure channel failure (Zerologon heuristic)", "Lateral Movement", "T1210", "Medium",
      "System events 5805/5829 from NETLOGON.")
def r_zerologon(ev):
    if ev["eid"] in (5805, 5829) and "netlogon" in (ev["provider"] or "").lower():
        return "Netlogon event %d on %s" % (ev["eid"], ev["host"])


# ------------------------------------------------------------ Command and Control
SUSP_DNS = (".ngrok.io", ".ngrok-free.app", ".duckdns.org", ".no-ip.org", ".ddns.net", ".hopto.org", ".serveo.net", ".trycloudflare.com")


@rule(_id(), "Dynamic DNS / tunnel domain queried", "Command and Control", "T1568", "Medium", "Sysmon 22 query to DDNS or tunnelling service.")
def r_dns_ddns(ev):
    q = get(ev, "QueryName").lower().rstrip(".")
    if is_sysmon(ev, 22) and q.endswith(SUSP_DNS):
        return "%s queried %s" % (base(get(ev, "Image")), q)


@rule(_id(), "DNS tunnelling heuristic", "Command and Control", "T1071.004", "Medium", "Very long labels or names in DNS queries.")
def r_dns_tunnel(ev):
    q = get(ev, "QueryName").lower().rstrip(".")
    if is_sysmon(ev, 22) and q and (max(len(x) for x in q.split(".")) > 50 or len(q) > 100):
        return "Suspicious DNS name length (%d): %s..." % (len(q), q[:60])


BAD_PORTS = {"4444", "4445", "1337", "31337", "6667", "6697", "9001", "9050", "12345"}


@rule(_id(), "Connection to non-standard C2 port", "Command and Control", "T1571", "Medium", "Outbound to a public IP on common implant ports.")
def r_ports(ev):
    if is_sysmon(ev, 3) and get(ev, "Initiated").lower() == "true" and get(ev, "DestinationPort") in BAD_PORTS \
            and is_public(get(ev, "DestinationIp")):
        return "%s -> %s:%s" % (base(get(ev, "Image")), get(ev, "DestinationIp"), get(ev, "DestinationPort"))


@rule(_id(), "C2 framework named pipe", "Command and Control", "T1090.001", "High",
      "Sysmon 17/18 pipe names used by Cobalt Strike, PsExec and similar tools.")
def r_pipes(ev):
    if ev["eid"] in (17, 18) and "sysmon" in ev["channel"].lower() and re.search(
            r"\\(msagent_[0-9a-f]+|postex_[0-9a-f]+|status_[0-9a-f]{2,}|msse-\d+-server|ntsvcs_[0-9a-f]+|scerpc_[0-9a-f]+|psexesvc|remcom|csexecsvc)",
            get(ev, "PipeName").lower()):
        return "Suspicious pipe %s by %s" % (get(ev, "PipeName"), base(get(ev, "Image")))


# ---------------------------------------------------------------- Exfiltration
EXFIL_DOMAINS = ("mega.nz", "mega.io", "transfer.sh", "anonfiles.com", "file.io", "gofile.io", "pastebin.com", "temp.sh",
                 "bashupload.com", "filebin.net", "ufile.io")


@rule(_id(), "File-sharing site contacted by non-browser", "Exfiltration", "T1567", "Medium",
      "Sysmon 22 query to anonymous file hosting from a non-browser process.")
def r_dns_exfil(ev):
    q = get(ev, "QueryName").lower().rstrip(".")
    if is_sysmon(ev, 22) and base(get(ev, "Image")) not in BROWSERS and any(q == d or q.endswith("." + d) for d in EXFIL_DOMAINS):
        return "%s queried %s" % (base(get(ev, "Image")), q)


@rule(_id(), "External storage device connected", "Exfiltration", "T1052.001", "Low", "Security 6416 removable disk.")
def r_usb(ev):
    if ev["eid"] == 6416 and (get(ev, "ClassName").lower() in ("diskdrive", "wpd") or "usb mass" in get(ev, "DeviceDescription").lower()):
        return "Device: " + (get(ev, "DeviceDescription") or get(ev, "ClassName"))


# ----------------------------------------------------------------------- Impact
RANSOM_RX = re.compile(r"how[_ -]?to[_ -]?(decrypt|recover|restore)|decrypt[_ -]?(instructions|files|my)|restore[_ -]?my[_ -]?files|"
                       r"readme[_ -]?to[_ -]?restore|ransom|recover[_ -]?your[_ -]?files")


@rule(_id(), "Ransom note created", "Impact", "T1486", "Critical", "Sysmon 11 file names typical of ransom notes.")
def r_ransom(ev):
    if is_sysmon(ev, 11) and RANSOM_RX.search(base(get(ev, "TargetFilename"))):
        return "Ransom note: " + get(ev, "TargetFilename")