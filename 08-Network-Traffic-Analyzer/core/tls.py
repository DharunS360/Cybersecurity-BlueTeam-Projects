"""TLS ClientHello parser: SNI + JA3 fingerprint (no scapy TLS layer needed)."""
import hashlib
import struct

GREASE = {0x0A0A + 0x1010 * i for i in range(16)}
TLS_VERSIONS = {0x0300: "SSL3", 0x0301: "TLS1.0", 0x0302: "TLS1.1", 0x0303: "TLS1.2", 0x0304: "TLS1.3"}


def parse_client_hello(p):
    """Return {sni, ja3, ja3_str, version} or None if payload is not a TLS ClientHello."""
    try:
        if len(p) < 45 or p[0] != 0x16 or p[5] != 0x01:
            return None
        pos = 9
        version = struct.unpack(">H", p[pos:pos + 2])[0]
        pos += 2 + 32
        pos += 1 + p[pos]                                   # session id
        cl = struct.unpack(">H", p[pos:pos + 2])[0]
        pos += 2
        ciphers = [struct.unpack(">H", p[pos + i:pos + i + 2])[0] for i in range(0, cl - 1, 2)]
        pos += cl
        pos += 1 + p[pos]                                   # compression
        exts, curves, ecpf, sni = [], [], [], ""
        if pos + 2 <= len(p):
            el = struct.unpack(">H", p[pos:pos + 2])[0]
            pos += 2
            end = min(pos + el, len(p))
            while pos + 4 <= end:
                et, ln = struct.unpack(">HH", p[pos:pos + 4])
                pos += 4
                data = p[pos:pos + ln]
                pos += ln
                exts.append(et)
                if et == 0 and len(data) >= 5:
                    nl = struct.unpack(">H", data[3:5])[0]
                    sni = data[5:5 + nl].decode("ascii", "ignore").lower()
                elif et == 10 and len(data) >= 2:
                    n = struct.unpack(">H", data[:2])[0]
                    curves = [struct.unpack(">H", data[2 + i:4 + i])[0] for i in range(0, n - 1, 2)]
                elif et == 11 and data:
                    ecpf = list(data[1:1 + data[0]])
        f = lambda xs: "-".join(str(x) for x in xs if x not in GREASE)
        s = "%d,%s,%s,%s,%s" % (version, f(ciphers), f(exts), f(curves), "-".join(str(x) for x in ecpf))
        return {"sni": sni, "ja3": hashlib.md5(s.encode()).hexdigest(), "ja3_str": s,
                "version": TLS_VERSIONS.get(version, hex(version))}
    except Exception:
        return None