"""
collectors.py - live artifact collection for Windows hosts.

Everything in this module reads the RUNNING system: psutil, the registry,
PowerShell/CIM, event logs and the filesystem. No sample or simulated data.
"""
import ctypes
import getpass
import hashlib
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import tempfile
import time
from datetime import datetime

import psutil

try:
    import winreg
except ImportError:  # not on Windows
    winreg = None

NOWIN = 0x08000000 if os.name == "nt" else 0
TS = "%Y-%m-%d %H:%M:%S"
SYSROOT = os.environ.get("SystemRoot", r"C:\Windows")
TOOL_NAME = "IR Triage Toolkit 1.0.0"


# --------------------------------------------------------------------------- helpers
def fmt_ts(epoch):
    try:
        return datetime.fromtimestamp(float(epoch)).strftime(TS)
    except Exception:
        return ""


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_ps(script, timeout=240):
    """Run a PowerShell snippet and return stdout as text ('' on failure)."""
    prefix = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
              "$ProgressPreference='SilentlyContinue';"
              "$ErrorActionPreference='SilentlyContinue';")
    try:
        r = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", prefix + script],
            capture_output=True, timeout=timeout, creationflags=NOWIN)
        return r.stdout.decode("utf-8-sig", "replace")
    except Exception:
        return ""


def ps_json(script, timeout=240):
    """Run PowerShell, convert whatever it emits to JSON and return a list of dicts."""
    out = run_ps("& { " + script + " } | ConvertTo-Json -Depth 4 -Compress", timeout).strip()
    if not out:
        return []
    try:
        data = json.loads(out)
    except Exception:
        return []
    if isinstance(data, dict):
        return [data]
    return [d for d in data if isinstance(d, dict)] if isinstance(data, list) else []


_HASH_CACHE = {}


def sha256_file(path, limit=150 * 1024 * 1024):
    if not path:
        return ""
    if path in _HASH_CACHE:
        return _HASH_CACHE[path]
    digest = ""
    try:
        if os.path.isfile(path) and os.path.getsize(path) <= limit:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            digest = h.hexdigest()
    except Exception:
        digest = ""
    _HASH_CACHE[path] = digest
    return digest


def scope_of(ip):
    if not ip:
        return ""
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return ""
    if a.is_loopback:
        return "Loopback"
    if a.is_unspecified or a.is_multicast:
        return "Other"
    if a.is_link_local or not a.is_global:
        return "Private"
    return "Public"


TARGET_RX = re.compile(
    r'^\s*"?((?:[A-Za-z]:|\\\\)[^"\r\n]*?\.(?:exe|dll|bat|cmd|ps1|vbs|vbe|js|jse|scr|com|hta|cpl|msi))',
    re.I)
BARE_RX = re.compile(r'^\s*"?([\w\-. ]+\.(?:exe|com))', re.I)


def extract_target(value):
    """Pull the executable path out of a command line / registry value."""
    v = os.path.expandvars(str(value or "")).replace("\\??\\", "")
    m = TARGET_RX.match(v)
    if m:
        return m.group(1).strip()
    m = BARE_RX.match(v)
    if m:
        for sub in ("System32", ""):
            p = os.path.join(SYSROOT, sub, m.group(1).strip())
            if os.path.isfile(p):
                return p
    return ""


def verify_signatures(rows, key="Path"):
    """Batch Authenticode verification. Adds Signature + Signer to each row in place."""
    paths = sorted({r[key] for r in rows if r.get(key) and os.path.isfile(r[key])})
    if not paths:
        return
    tmp = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
    try:
        tmp.write("\n".join(paths))
        tmp.close()
        script = ("$r=foreach($p in Get-Content -LiteralPath '__F__' -Encoding UTF8){"
                  "$s=Get-AuthenticodeSignature -LiteralPath $p;"
                  "[pscustomobject]@{Path=[string]$p;Status=[string]$s.Status;"
                  "Signer=[string]$s.SignerCertificate.Subject}};$r").replace(
                      "__F__", tmp.name.replace("'", "''"))
        result = {}
        for d in ps_json(script, timeout=420):
            def _v(x):
                if isinstance(x, dict):
                    x = x.get("value", "")
                return str(x or "")
            m = re.search(r"CN=([^,]+)", _v(d.get("Signer")))
            result[_v(d.get("Path")).lower()] = (_v(d.get("Status")),
                                                 m.group(1).strip('" ') if m else "")
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
    for r in rows:
        p = (r.get(key) or "").lower()
        if p in result:
            r["Signature"], r["Signer"] = result[p]


# --------------------------------------------------------------------------- meta
def collect_meta(opts):
    host = socket.gethostname()
    try:
        ips = sorted({a[4][0] for a in socket.getaddrinfo(host, None) if ":" not in a[4][0]})
    except Exception:
        ips = []
    now = datetime.now()
    return {
        "Tool": TOOL_NAME,
        "Hostname": host,
        "Analyst": opts.get("analyst") or getpass.getuser(),
        "CurrentUser": getpass.getuser(),
        "OS": platform.platform(),
        "Build": platform.version(),
        "Architecture": platform.machine(),
        "IPAddresses": ", ".join(ips),
        "BootTime": fmt_ts(psutil.boot_time()),
        "Timezone": time.tzname[0],
        "Admin": is_admin(),
        "CollectionStartLocal": now.strftime(TS),
        "CollectionStartUTC": datetime.utcnow().strftime(TS),
        "EventWindowHours": opts.get("hours", 24),
        "FileWindowDays": opts.get("days", 7),
        "Warnings": [],
    }


# --------------------------------------------------------------------------- processes
def collect_processes():
    snap = {}
    attrs = ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]
    for p in psutil.process_iter(attrs):
        snap[p.info["pid"]] = p.info
    rows = []
    for pid, i in snap.items():
        par = snap.get(i.get("ppid") if i.get("ppid") is not None else -1)
        pname = ppath = ""
        if par and (par.get("create_time") or 0) <= (i.get("create_time") or 0) + 1:
            pname, ppath = par.get("name") or "", par.get("exe") or ""
        exe = i.get("exe") or ""
        rows.append({
            "Severity": "", "PID": pid, "PPID": i.get("ppid") or 0,
            "Name": i.get("name") or "", "Parent": pname, "ParentPath": ppath,
            "User": i.get("username") or "", "Path": exe,
            "CmdLine": subprocess.list2cmdline(i.get("cmdline") or []),
            "Started": fmt_ts(i.get("create_time") or 0),
            "SHA256": sha256_file(exe) if exe else "",
            "Signature": "", "Signer": "", "Flags": "",
        })
    return rows


# --------------------------------------------------------------------------- network
def collect_network(procs):
    pmap = {r["PID"]: r for r in procs}
    rows = []
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        conns = []
    for c in conns:
        pr = pmap.get(c.pid or 0, {})
        rip = c.raddr.ip if c.raddr else ""
        rows.append({
            "Severity": "",
            "Proto": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
            "Local": c.laddr.ip if c.laddr else "", "LPort": c.laddr.port if c.laddr else 0,
            "Remote": rip, "RPort": c.raddr.port if c.raddr else 0, "Hostname": "",
            "State": "" if c.status == "NONE" else c.status,
            "PID": c.pid or 0, "Process": pr.get("Name", ""), "Path": pr.get("Path", ""),
            "Scope": scope_of(rip), "Signature": pr.get("Signature", ""), "Flags": "",
        })
    return rows


# --------------------------------------------------------------------------- registry / persistence
def _hive(name):
    return winreg.HKEY_LOCAL_MACHINE if name == "HKLM" else winreg.HKEY_CURRENT_USER


def _s(v):
    if isinstance(v, bytes):
        return v.decode("utf-16-le", "ignore") if b"\x00" in v else v.decode("utf-8", "ignore")
    if isinstance(v, (list, tuple)):
        return " ".join(str(x) for x in v)
    return str(v)


def reg_values(hive, path):
    out = []
    if not winreg:
        return out
    try:
        with winreg.OpenKey(_hive(hive), path, 0, winreg.KEY_READ) as k:
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(k, i)
                except OSError:
                    break
                out.append((name, _s(val)))
                i += 1
    except OSError:
        pass
    return out


def reg_subkeys(hive, path):
    out = []
    if not winreg:
        return out
    try:
        with winreg.OpenKey(_hive(hive), path, 0, winreg.KEY_READ) as k:
            i = 0
            while True:
                try:
                    out.append(winreg.EnumKey(k, i))
                except OSError:
                    break
                i += 1
    except OSError:
        pass
    return out


RUN_KEYS = [
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
]

TASK_PS = r"""
Get-ScheduledTask | ForEach-Object {
  $t=$_
  $acts=@($t.Actions | ForEach-Object { (([string]$_.Execute) + ' ' + ([string]$_.Arguments)).Trim() }) -join ' ; '
  [pscustomobject]@{Name=[string]$t.TaskName;Path=[string]$t.TaskPath;State=[string]$t.State;RunAs=[string]$t.Principal.UserId;Action=$acts}
}
"""

WMI_PS = r"""
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer | ForEach-Object {
  [pscustomobject]@{Name=[string]$_.Name;Class=[string]$_.CimClass.CimClassName;Command=[string]$_.CommandLineTemplate;Script=[string]$_.ScriptText;Exe=[string]$_.ExecutablePath}
}
"""


def collect_persistence():
    rows = []

    def add(typ, name, loc, val, ctx="", mtime=""):
        rows.append({"Severity": "", "Type": typ, "Name": name, "Location": loc, "Value": val,
                     "Target": extract_target(val) if typ != "WMI Subscription" else "",
                     "Signature": "", "Signer": "", "Context": ctx, "Modified": mtime, "Flags": ""})

    # Run / RunOnce keys
    for hive, path in RUN_KEYS:
        for name, val in reg_values(hive, path):
            add("Registry Run Key", name, hive + "\\" + path, val, hive)

    # Winlogon helper values
    wl = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    for name, val in reg_values("HKLM", wl):
        if name in ("Shell", "Userinit", "Taskman", "VmApplet"):
            add("Winlogon", name, "HKLM\\" + wl, val, "HKLM")

    # AppInit DLLs
    for hive in ("HKLM",):
        for sub in (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
                    r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows"):
            for name, val in reg_values(hive, sub):
                if name == "AppInit_DLLs" and val.strip():
                    add("AppInit", name, hive + "\\" + sub, val, hive)

    # Image File Execution Options debuggers
    ifeo = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    for sk in reg_subkeys("HKLM", ifeo):
        for name, val in reg_values("HKLM", ifeo + "\\" + sk):
            if name.lower() == "debugger" and val.strip():
                add("IFEO", sk, "HKLM\\" + ifeo + "\\" + sk, val, "HKLM")

    # cmd.exe AutoRun
    for hive in ("HKLM", "HKCU"):
        for name, val in reg_values(hive, r"SOFTWARE\Microsoft\Command Processor"):
            if name.lower() == "autorun" and val.strip():
                add("Command Processor AutoRun", name, hive + r"\SOFTWARE\Microsoft\Command Processor", val, hive)

    # Startup folders
    folders = [os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
               os.path.join(os.environ.get("PROGRAMDATA", ""), r"Microsoft\Windows\Start Menu\Programs\StartUp")]
    for d in folders:
        try:
            for ent in os.scandir(d):
                if ent.name.lower() == "desktop.ini":
                    continue
                add("Startup Folder", ent.name, d, ent.path, "User" if "AppData" in d else "AllUsers",
                    fmt_ts(ent.stat().st_mtime))
        except OSError:
            pass

    # Services
    if hasattr(psutil, "win_service_iter"):
        for svc in psutil.win_service_iter():
            try:
                d = svc.as_dict()
            except Exception:
                continue
            binpath = d.get("binpath") or ""
            if not binpath:
                continue
            add("Service", d.get("name", ""), "Services: " + (d.get("display_name") or ""), binpath,
                "%s / %s / %s" % (d.get("start_type", ""), d.get("status", ""), d.get("username", "")))

    # Scheduled tasks
    for t in ps_json(TASK_PS, timeout=300):
        add("Scheduled Task", (t.get("Path") or "") + (t.get("Name") or ""), "Task Scheduler",
            t.get("Action") or "", "%s / %s" % (t.get("RunAs") or "", t.get("State") or ""))

    # WMI event subscription consumers (classic fileless persistence)
    for w in ps_json(WMI_PS, timeout=120):
        val = w.get("Command") or w.get("Script") or w.get("Exe") or ""
        add("WMI Subscription", w.get("Name") or "", "root\\subscription (%s)" % w.get("Class", ""), val, "WMI")
    return rows


# --------------------------------------------------------------------------- system artifacts
ARTIFACT_PS = r"""
Get-LocalUser | ForEach-Object { [pscustomobject]@{Cat='User';Name=[string]$_.Name;A=[string]$_.Enabled;B=$(if($_.LastLogon){$_.LastLogon.ToString('yyyy-MM-dd HH:mm:ss')}else{''});C=$(if($_.PasswordLastSet){$_.PasswordLastSet.ToString('yyyy-MM-dd HH:mm:ss')}else{''});D=[string]$_.Description} }
Get-LocalGroupMember -SID S-1-5-32-544 | ForEach-Object { [pscustomobject]@{Cat='Admin';Name=[string]$_.Name;A=[string]$_.ObjectClass;B=[string]$_.PrincipalSource;C='';D=''} }
Get-DnsClientCache | ForEach-Object { [pscustomobject]@{Cat='DNS';Name=[string]$_.Entry;A=[string]$_.Type;B=[string]$_.Data;C='';D=''} }
Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.State -ne 'Unreachable' } | ForEach-Object { [pscustomobject]@{Cat='ARP';Name=[string]$_.IPAddress;A=[string]$_.LinkLayerAddress;B=[string]$_.State;C='';D=''} }
Get-SmbShare | ForEach-Object { [pscustomobject]@{Cat='Share';Name=[string]$_.Name;A=[string]$_.Path;B=[string]$_.Description;C='';D=''} }
Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{Cat='Firewall';Name=[string]$_.Name;A=[string]$_.Enabled;B='';C='';D=''} }
$s=Get-MpComputerStatus; $p=Get-MpPreference
if($s){ [pscustomobject]@{Cat='Defender';Name='Status';A=[string]$s.AntivirusEnabled;B=[string]$s.RealTimeProtectionEnabled;C=[string]$s.AntivirusSignatureAge;D=''} }
if($p){
  foreach($x in @($p.ExclusionPath)){ if($x){ [pscustomobject]@{Cat='DefenderExclusion';Name='Path';A=[string]$x;B='';C='';D=''} } }
  foreach($x in @($p.ExclusionProcess)){ if($x){ [pscustomobject]@{Cat='DefenderExclusion';Name='Process';A=[string]$x;B='';C='';D=''} } }
  foreach($x in @($p.ExclusionExtension)){ if($x){ [pscustomobject]@{Cat='DefenderExclusion';Name='Extension';A=[string]$x;B='';C='';D=''} } }
}
"""


def collect_artifacts():
    rows = []

    def add(cat, name, detail, when=""):
        rows.append({"Severity": "", "Category": cat, "Name": name, "Detail": detail, "Time": when, "Flags": ""})

    for d in ps_json(ARTIFACT_PS, timeout=240):
        cat, name = d.get("Cat"), d.get("Name") or ""
        a, b, c, dd = (d.get(k) or "" for k in ("A", "B", "C", "D"))
        if cat == "User":
            add("Local User", name, "Enabled=%s; PasswordLastSet=%s; %s" % (a, c, dd), b)
        elif cat == "Admin":
            add("Local Administrator", name, "%s (%s)" % (a, b))
        elif cat == "DNS":
            add("DNS Cache", name, "Type %s -> %s" % (a, b))
        elif cat == "ARP":
            add("ARP Neighbor", name, "MAC=%s State=%s" % (a, b))
        elif cat == "Share":
            add("SMB Share", name, "%s %s" % (a, b))
        elif cat == "Firewall":
            add("Firewall Profile", name, "Enabled=%s" % a)
        elif cat == "Defender":
            add("Defender", "Status", "AV enabled=%s; Real-time=%s; Signature age (days)=%s" % (a, b, c))
        elif cat == "DefenderExclusion":
            add("Defender Exclusion", name, a)

    # Logged-on sessions
    try:
        for u in psutil.users():
            add("Logged-on Session", u.name, "Terminal=%s Host=%s" % (u.terminal or "", u.host or ""), fmt_ts(u.started))
    except Exception:
        pass

    # RDP enabled?
    for name, val in reg_values("HKLM", r"SYSTEM\CurrentControlSet\Control\Terminal Server"):
        if name == "fDenyTSConnections":
            add("Remote Desktop", "fDenyTSConnections", "RDP %s" % ("DISABLED" if str(val) == "1" else "ENABLED"))

    # hosts file
    hosts = os.path.join(SYSROOT, r"System32\drivers\etc\hosts")
    try:
        mt = fmt_ts(os.path.getmtime(hosts))
        with open(hosts, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    add("Hosts File", hosts, line, mt)
    except OSError:
        pass
    return rows


# --------------------------------------------------------------------------- files & execution traces
EXEC_EXT = {".exe", ".dll", ".scr", ".com", ".cpl", ".msi", ".sys"}
SCRIPT_EXT = {".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".hta", ".wsf", ".jar"}
OTHER_EXT = {".lnk", ".iso", ".img", ".zip", ".rar", ".7z", ".docm", ".xlsm", ".pptm"}
INTEREST = EXEC_EXT | SCRIPT_EXT | OTHER_EXT
SKIP_DIRS = {"node_modules", ".git", "cache", "code cache", "gpucache", "crashpad", "__pycache__",
             "site-packages", "microsoft", "windowsapps", "packages", "npm-cache"}


def _scan_dirs():
    e = os.environ
    root = os.path.join(e.get("SystemDrive", "C:") + "\\", "Users")
    dirs = set()
    try:
        profiles = [os.path.join(root, d) for d in os.listdir(root)]
    except OSError:
        profiles = [e.get("USERPROFILE", "")]
    for pr in profiles:
        for sub in ("Downloads", "Desktop", "Documents", r"AppData\Roaming", r"AppData\Local\Temp"):
            dirs.add(os.path.join(pr, sub))
    dirs.update({os.path.join(root, "Public"), os.path.join(SYSROOT, "Temp"), e.get("PROGRAMDATA", "")})
    return sorted(d for d in dirs if d and os.path.isdir(d))


def collect_files(days, hash_files=True, max_rows=2500, max_hash=400):
    cutoff = time.time() - days * 86400
    rows = []
    for base in _scan_dirs():
        base_depth = base.rstrip("\\").count("\\")
        for root, dirs, files in os.walk(base, onerror=lambda err: None):
            dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS and root.count("\\") - base_depth < 4]
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext not in INTEREST:
                    continue
                fp = os.path.join(root, f)
                try:
                    st = os.stat(fp)
                except OSError:
                    continue
                if max(st.st_mtime, st.st_ctime) < cutoff:
                    continue
                rows.append({"Severity": "", "Kind": "Dropped File", "Name": f, "Path": fp, "Size": st.st_size,
                             "Created": fmt_ts(st.st_ctime), "Modified": fmt_ts(st.st_mtime),
                             "SHA256": "", "Signature": "", "Signer": "", "Flags": ""})
                if len(rows) >= max_rows:
                    break
            if len(rows) >= max_rows:
                break
        if len(rows) >= max_rows:
            break
    rows.sort(key=lambda r: r["Modified"], reverse=True)
    if hash_files:
        n = 0
        for r in rows:
            ext = os.path.splitext(r["Name"])[1].lower()
            if ext in EXEC_EXT | SCRIPT_EXT and r["Size"] <= 100 * 1024 * 1024:
                r["SHA256"] = sha256_file(r["Path"])
                n += 1
                if n >= max_hash:
                    break
    return rows


def collect_execution_traces(days):
    """Prefetch (needs admin) and Recent-LNK evidence of program execution / file access."""
    cutoff = time.time() - days * 86400
    rows, pf_ok = [], True
    pf = os.path.join(SYSROOT, "Prefetch")
    try:
        for ent in os.scandir(pf):
            if ent.name.lower().endswith(".pf"):
                st = ent.stat()
                if st.st_mtime >= cutoff:
                    rows.append({"Severity": "", "Kind": "Prefetch", "Name": ent.name.rsplit("-", 1)[0],
                                 "Path": ent.path, "Size": st.st_size, "Created": fmt_ts(st.st_ctime),
                                 "Modified": fmt_ts(st.st_mtime), "SHA256": "", "Signature": "", "Signer": "", "Flags": ""})
    except OSError:
        pf_ok = False
    recent = os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Recent")
    try:
        for ent in os.scandir(recent):
            if ent.name.lower().endswith(".lnk"):
                st = ent.stat()
                if st.st_mtime >= cutoff:
                    rows.append({"Severity": "", "Kind": "Recent LNK", "Name": ent.name, "Path": ent.path,
                                 "Size": st.st_size, "Created": fmt_ts(st.st_ctime), "Modified": fmt_ts(st.st_mtime),
                                 "SHA256": "", "Signature": "", "Signer": "", "Flags": ""})
    except OSError:
        pass
    rows.sort(key=lambda r: r["Modified"], reverse=True)
    return rows[:700], pf_ok


# --------------------------------------------------------------------------- event logs
EVT_PS = r"""
$since=(Get-Date).AddHours(-__H__)
function Cut($s,$n){ $s=([string]$s -replace '\s+',' ').Trim(); if($s.Length -gt $n){$s.Substring(0,$n)}else{$s} }
function Emit($e,$d){ [pscustomobject]@{Time=$e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss');Log=[string]$e.LogName;EventID=[int]$e.Id;Provider=[string]$e.ProviderName;Detail=(Cut $d 700);Message=(Cut $e.Message 350)} }
if('__SEC__' -eq '1'){
  Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102,4624,4625,4688,4697,4698,4720,4728,4732,4756;StartTime=$since} -MaxEvents 5000 | ForEach-Object {
    $e=$_; $p=$e.Properties; $d=''
    switch($e.Id){
      4624 { $lt=[int]$p[8].Value; $u=[string]$p[5].Value
             if(($lt -notin 2,3,9,10) -or $u.EndsWith('$') -or $u -eq 'ANONYMOUS LOGON'){ return }
             $d="User=$u LogonType=$lt Src=$($p[18].Value) Proc=$($p[17].Value)" }
      4625 { $d="User=$($p[5].Value) LogonType=$($p[10].Value) Src=$($p[19].Value) Status=$($p[7].Value)" }
      4688 { $d="Proc=$($p[5].Value) Parent=$($p[13].Value) Cmd=$($p[8].Value)" }
      4697 { $d="Service=$($p[4].Value) Path=$($p[5].Value) By=$($p[1].Value)" }
      4698 { $d="Task=$($p[4].Value) By=$($p[1].Value)" }
      4720 { $d="NewAccount=$($p[0].Value) By=$($p[4].Value)" }
      4728 { $d="Member=$($p[0].Value) Group=$($p[2].Value) By=$($p[6].Value)" }
      4732 { $d="Member=$($p[0].Value) Group=$($p[2].Value) By=$($p[6].Value)" }
      4756 { $d="Member=$($p[0].Value) Group=$($p[2].Value) By=$($p[6].Value)" }
    }
    Emit $e $d
  }
}
Get-WinEvent -FilterHashtable @{LogName='System';Id=7045,104;StartTime=$since} -MaxEvents 500 | ForEach-Object {
  $e=$_; $p=$e.Properties; $d=''
  if($e.Id -eq 7045){ $d="Service=$($p[0].Value) Path=$($p[1].Value) Account=$($p[4].Value)" }
  Emit $e $d
}
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104;StartTime=$since} -MaxEvents 1500 | ForEach-Object {
  Emit $_ (Cut $_.Properties[2].Value 700)
}
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';Id=1116,1117,5001;StartTime=$since} -MaxEvents 300 | ForEach-Object {
  Emit $_ ''
}
"""

PS_SUSP = re.compile(
    r"(?i)(downloadstring|downloadfile|frombase64string|invoke-expression|\biex\b|invoke-mimikatz|"
    r"net\.webclient|virtualalloc|amsiutils|amsiinitfailed|reflection\.assembly|invoke-shellcode|"
    r"set-mppreference|-enc(odedcommand)?\s|invoke-webrequest|start-bitstransfer)")


def collect_events(hours, include_security=True):
    script = EVT_PS.replace("__H__", str(int(hours))).replace("__SEC__", "1" if include_security else "0")
    rows = []
    for r in ps_json(script, timeout=600):
        if r.get("EventID") == 4104 and not PS_SUSP.search(r.get("Detail") or ""):
            continue
        r["Severity"], r["Flags"] = "", ""
        rows.append(r)
    rows.sort(key=lambda r: r.get("Time", ""), reverse=True)
    return rows
