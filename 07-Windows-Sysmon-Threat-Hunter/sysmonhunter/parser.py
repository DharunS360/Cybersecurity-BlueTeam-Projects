"""Event ingestion: EVTX files, live wevtutil export and XML normalisation."""
import ctypes
import re
import subprocess
from defusedxml import ElementTree as ET
from datetime import datetime

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

LIVE_CHANNELS = [
    "Microsoft-Windows-Sysmon/Operational",
    "Security",
    "System",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
]


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def parse_time(value):
    """Parse Windows Event XML timestamps into naive UTC datetimes."""
    value = (value or "").strip()
    if not value:
        return None
    try:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is not None:
            from datetime import timezone
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except (ValueError, OverflowError):
        m = re.match(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(\.\d+)?", value)
        if not m:
            return None
        frac = (m.group(3) or ".0")[:7]
        try:
            return datetime.strptime("%s %s%s" % (m.group(1), m.group(2), frac),
                                     "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            return None


def event_from_element(root):
    """Convert an <Event> XML element into a normalised dict."""
    system = root.find(NS + "System")
    if system is None:
        return None

    def text(tag):
        el = system.find(NS + tag)
        return (el.text or "").strip() if el is not None and el.text else ""

    try:
        eid = int((text("EventID") or "0").split()[0])
    except (ValueError, IndexError):
        return None
    tc = system.find(NS + "TimeCreated")
    event_time = parse_time(tc.get("SystemTime") if tc is not None else "")
    if event_time is None:
        return None
    prov = system.find(NS + "Provider")
    data = {}
    for container in ("EventData", "UserData"):
        node = root.find(NS + container)
        if node is None:
            continue
        for el in node.iter():
            if el is node:
                continue
            tag = el.tag.split("}")[-1]
            if tag == "Data":
                name = el.get("Name")
                if name:
                    data[name] = (el.text or "").strip()
            elif len(el) == 0 and el.text and el.text.strip():
                data[tag] = el.text.strip()
    return {
        "time": event_time,
        "eid": eid,
        "channel": text("Channel"),
        "provider": prov.get("Name") if prov is not None else "",
        "host": text("Computer") or "UNKNOWN",
        "record_id": text("EventRecordID"),
        "data": data,
    }


def read_evtx(path):
    try:
        from Evtx.Evtx import Evtx
    except ImportError:
        raise SystemExit("python-evtx is not installed. Run: pip install -r requirements.txt")
    events = []
    with Evtx(path) as log:
        for rec in log.records():
            try:
                ev = event_from_element(ET.fromstring(rec.xml()))
            except Exception:
                continue
            if ev:
                events.append(ev)
    return events


def read_live(channel, max_events=3000):
    """Export the newest events of an explicitly supported channel."""
    if channel not in LIVE_CHANNELS:
        return [], "Unsupported event channel."
    max_events = max(1, min(50000, int(max_events)))
    cmd = ["wevtutil", "qe", channel, "/c:%d" % max_events, "/rd:true", "/f:xml"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=180)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], str(exc)
    if proc.returncode != 0:
        return [], (proc.stderr or proc.stdout).strip()
    xml = re.sub(r"<\?xml[^>]*\?>", "", proc.stdout)
    try:
        root = ET.fromstring("<Events>" + xml + "</Events>")
    except ET.ParseError as exc:
        return [], "XML parse error: %s" % exc
    return [e for e in (event_from_element(x) for x in root) if e], ""