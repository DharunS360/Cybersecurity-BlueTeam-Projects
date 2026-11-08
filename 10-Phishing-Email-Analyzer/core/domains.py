"""Small domain helpers (no external public-suffix dependency)."""
_SLD = {"co", "com", "org", "net", "gov", "edu", "ac", "nic", "res", "ne", "or",
        "go", "ltd", "plc", "mil", "gen", "firm", "ind"}


def org_domain(host):
    """Approximate organizational (registrable) domain."""
    host = (host or "").strip(".").lower()
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if len(parts[-1]) == 2 and parts[-2] in _SLD:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def domain_of(addr):
    addr = (addr or "").strip().strip("<>")
    return addr.rsplit("@", 1)[1].lower() if "@" in addr else ""


def aligned(a, b, strict=False):
    a, b = (a or "").lower(), (b or "").lower()
    if not a or not b:
        return False
    return a == b if strict else org_domain(a) == org_domain(b)


def defang(s):
    s = str(s)
    return s.replace("http", "hxxp").replace(".", "[.]").replace("@", "[@]")
