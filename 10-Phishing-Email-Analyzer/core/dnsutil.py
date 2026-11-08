"""Thin, cached wrapper around dnspython (live DNS queries)."""
from functools import lru_cache

import dns.exception
import dns.resolver


@lru_cache(maxsize=1024)
def _q(name, rtype, timeout):
    try:
        res = dns.resolver.Resolver()
        res.lifetime = timeout
        res.timeout = timeout
        ans = res.resolve(name, rtype)
        out = []
        for rd in ans:
            if rtype == "TXT":
                out.append(b"".join(rd.strings).decode("utf-8", "replace"))
            elif rtype == "MX":
                out.append(str(rd.exchange).rstrip("."))
            else:
                out.append(rd.to_text())
        return tuple(out), "ok"
    except dns.resolver.NXDOMAIN:
        return (), "nxdomain"
    except dns.resolver.NoAnswer:
        return (), "nodata"
    except dns.exception.Timeout:
        return (), "timeout"
    except Exception:
        return (), "error"


def query(name, rtype="TXT", timeout=4.0):
    """Return (list_of_strings, status). status: ok|nxdomain|nodata|timeout|error"""
    out, status = _q(name.rstrip("."), rtype, float(timeout))
    return list(out), status
