"""Static attachment triage. Attachments are NEVER executed or opened by an application."""
import hashlib
import io
import math
import re
import zipfile

DANGEROUS = {"exe", "scr", "com", "pif", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh",
             "hta", "lnk", "jar", "msi", "dll", "cpl", "reg", "chm", "iso", "img", "vhd", "vhdx", "one",
             "appx", "msix", "gadget", "inf", "sct", "url", "xll", "wll", "ocx", "sys", "apk"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "ppam", "sldm"}
HTML_EXT = {"html", "htm", "xhtml", "svg", "shtml", "mht", "mhtml"}
EXPECTED = {"pdf": {"pdf"}, "png": {"png"}, "jpg": {"jpg"}, "jpeg": {"jpg"}, "gif": {"gif"},
            "docx": {"zip"}, "xlsx": {"zip"}, "pptx": {"zip"}, "zip": {"zip"}, "jar": {"zip"},
            "doc": {"ole", "zip"}, "xls": {"ole", "zip"}, "ppt": {"ole", "zip"},
            "exe": {"pe"}, "dll": {"pe"}, "scr": {"pe"}, "rar": {"rar"}, "7z": {"7z"}, "rtf": {"rtf"},
            "lnk": {"lnk"}, "gz": {"gzip"}, "bmp": {"bmp"}}
MAGIC = ((b"MZ", "pe"), (b"%PDF", "pdf"), (b"PK\x03\x04", "zip"), (b"\xd0\xcf\x11\xe0", "ole"),
         (b"Rar!", "rar"), (b"7z\xbc\xaf", "7z"), (b"\x1f\x8b", "gzip"), (b"\x89PNG", "png"),
         (b"\xff\xd8\xff", "jpg"), (b"GIF8", "gif"), (b"L\x00\x00\x00\x01\x14\x02\x00", "lnk"),
         (b"{\\rtf", "rtf"), (b"\x7fELF", "elf"), (b"BM", "bmp"))
DOUBLE_EXT = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|rtf|csv)\s*\.(exe|scr|js|jse|vbs|vbe|bat|cmd|com|pif|lnk|hta|ps1|jar|msi)$", re.I)
AUTOEXEC = (b"AutoOpen", b"Document_Open", b"Workbook_Open", b"Auto_Open", b"AutoExec", b"Document_Close")
SUSP_MACRO = (b"CreateObject", b"Shell", b"powershell", b"WScript", b"URLDownloadToFile", b"Environ",
              b"cmd.exe", b"MSXML2", b"ADODB.Stream")


def _flag(code, text, sev, pts, mitre=None):
    return {"code": code, "text": text, "sev": sev, "pts": pts, "mitre": mitre}


def _has(data, s):
    return s in data or s.decode("latin-1").encode("utf-16le") in data


def entropy(data):
    data = data[:1_000_000]
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def detect_kind(data):
    for sig, name in MAGIC:
        if data.startswith(sig):
            return name
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "iso"
    head = data[:4096].lower()
    if b"<svg" in head:
        return "svg"
    if b"<html" in head or b"<script" in head or b"<!doctype html" in head:
        return "html"
    try:
        data[:2000].decode("utf-8")
        return "text"
    except UnicodeDecodeError:
        return "unknown"


def analyze_bytes(filename, ctype, data):
    name = filename or "(unnamed)"
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    kind = detect_kind(data)
    flags, details, urls = [], [], []
    ent = entropy(data)

    if "\u202e" in name:
        flags.append(_flag("RLO_NAME", "Right-to-left override char in filename (extension spoofing)", "high", 30, "T1036.002"))
    if DOUBLE_EXT.search(name.strip()):
        flags.append(_flag("DOUBLE_EXT", "Double extension disguises an executable", "high", 30, "T1036.007"))
    if ext in DANGEROUS:
        flags.append(_flag("DANGEROUS_EXT", f"High-risk file type .{ext}", "high", 30, "T1204.002"))
    if ext in MACRO_EXT:
        flags.append(_flag("MACRO_EXT", f"Macro-enabled Office file .{ext}", "high", 25, "T1204.002"))
    if ext in EXPECTED and kind not in EXPECTED[ext] and kind != "text":
        sev, pts = ("high", 30) if kind in ("pe", "elf", "lnk") else ("medium", 15)
        flags.append(_flag("TYPE_MISMATCH", f"Extension .{ext} but content is '{kind}'", sev, pts, "T1036.008"))
    if kind == "pe" and ext not in ("exe", "dll", "scr"):
        details.append("Windows PE executable detected inside non-executable filename")

    if kind == "zip":
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
            names = zf.namelist()
            details.append(f"ZIP/OOXML with {len(names)} entries")
            if any(i.flag_bits & 0x1 for i in zf.infolist()):
                flags.append(_flag("ENCRYPTED_ARCHIVE", "Password-protected archive (bypasses scanners)", "medium", 15, "T1027.013"))
            inner = [n for n in names if n.rsplit(".", 1)[-1].lower() in DANGEROUS]
            if inner:
                flags.append(_flag("ARCHIVE_EXEC", f"Archive contains executable/script: {', '.join(inner[:3])}", "high", 25, "T1204.002"))
            if any(n.lower().endswith("vbaproject.bin") for n in names):
                flags.append(_flag("VBA_MACRO", "OOXML document contains VBA macro project", "high", 25, "T1059.005"))
            for n in names:
                if n.lower().endswith(".rels"):
                    try:
                        rels = zf.read(n).decode("utf-8", "ignore")
                    except Exception:
                        continue
                    for m in re.finditer(r'Type="[^"]*/(attachedTemplate|oleObject|externalLink|frame)"[^>]*Target="([^"]+)"[^>]*TargetMode="External"', rels):
                        urls.append(m.group(2))
                        flags.append(_flag("REMOTE_TEMPLATE", f"Remote {m.group(1)} reference: {m.group(2)[:90]}", "high", 30, "T1221"))
        except zipfile.BadZipFile:
            details.append("Corrupt or truncated ZIP structure")
    elif kind == "ole":
        if _has(data, b"VBA") or _has(data, b"_VBA_PROJECT") or _has(data, b"Macros"):
            flags.append(_flag("VBA_MACRO", "Legacy OLE document contains VBA macro storage", "high", 25, "T1059.005"))
        auto = [a.decode() for a in AUTOEXEC if _has(data, a)]
        if auto:
            flags.append(_flag("AUTOEXEC_MACRO", f"Auto-execute macro entry points: {', '.join(auto)}", "high", 15, "T1204.002"))
        susp = [a.decode() for a in SUSP_MACRO if _has(data, a)]
        if susp:
            flags.append(_flag("SUSP_MACRO_API", f"Suspicious macro strings: {', '.join(susp)}", "high", 15, "T1059.005"))
    elif kind == "pdf":
        txt = data.decode("latin-1", "ignore")
        for key, pts, desc in (("/JavaScript", 20, "embedded JavaScript"), ("/JS", 0, ""), ("/Launch", 25, "launch action"),
                               ("/OpenAction", 8, "auto-run action on open"), ("/EmbeddedFile", 15, "embedded file")):
            if key in txt and pts:
                flags.append(_flag("PDF_" + key.strip("/").upper(), f"PDF contains {desc} ({key})", "high" if pts >= 20 else "medium", pts, "T1204.002"))
        urls.extend(re.findall(r"/URI\s*\(([^)]{4,300})\)", txt))
        if urls:
            details.append(f"{len(urls)} URI action(s) inside PDF")
        if "/ObjStm" in txt:
            details.append("Object streams present (keyword scan may be incomplete)")
    elif kind in ("html", "svg") or ext in HTML_EXT:
        txt = data[:2_000_000].decode("latin-1", "ignore").lower()
        smug = [k for k in ("atob(", "blob(", "createobjecturl", "mssaveorOpenblob".lower(), "eval(", "fromcharcode") if k in txt]
        if "atob(" in txt and ("blob(" in txt or "createobjecturl" in txt):
            flags.append(_flag("HTML_SMUGGLING", "HTML smuggling pattern (atob + Blob download)", "high", 28, "T1027.006"))
        elif smug:
            flags.append(_flag("HTML_OBFUSC", f"Obfuscation-prone script APIs: {', '.join(smug)}", "medium", 10, "T1027"))
        if 'type="password"' in txt or "type='password'" in txt:
            flags.append(_flag("HTML_CRED_FORM", "Attachment contains a password form (credential harvesting page)", "high", 30, "T1566.001"))
        urls.extend(re.findall(r"https?://[^\s\"'<>]{4,200}", txt)[:15])
    elif kind == "unknown" and ent > 7.2:
        flags.append(_flag("HIGH_ENTROPY", f"High entropy ({ent:.2f}) unknown content (packed/encrypted)", "medium", 8, "T1027"))

    return {"filename": name, "content_type": ctype, "size": len(data), "ext": ext, "kind": kind,
            "entropy": round(ent, 2), "md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(), "flags": flags, "details": details,
            "urls": list(dict.fromkeys(urls))[:20], "vt": None}


def extract(msg):
    out = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        try:
            fn = part.get_filename()
        except Exception:
            fn = None
        disp = part.get_content_disposition() or ""
        ctype = part.get_content_type()
        if not fn and disp != "attachment" and ctype in ("text/plain", "text/html"):
            continue
        try:
            data = part.get_payload(decode=True) or b""
        except Exception:
            data = b""
        if not data:
            continue
        out.append(analyze_bytes(fn, ctype, data))
    return out
