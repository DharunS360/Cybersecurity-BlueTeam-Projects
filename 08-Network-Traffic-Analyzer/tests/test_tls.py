import struct

from core.tls import parse_client_hello


def build_hello(sni, ciphers=(0x0A0A, 0xC02B, 0xC02F)):
    name = sni.encode()
    sn = struct.pack(">HBH", len(name) + 3, 0, len(name)) + name
    ext = struct.pack(">HH", 0, len(sn)) + sn
    ext += struct.pack(">HH", 10, 4) + struct.pack(">HH", 2, 23)
    ext += struct.pack(">HH", 11, 2) + bytes([1, 0])
    cs = b"".join(struct.pack(">H", c) for c in ciphers)
    body = (struct.pack(">H", 0x0303) + b"\x01" * 32 + b"\x00" + struct.pack(">H", len(cs)) + cs +
            b"\x01\x00" + struct.pack(">H", len(ext)) + ext)
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def test_sni_and_ja3_string():
    ch = parse_client_hello(build_hello("example.org"))
    assert ch["sni"] == "example.org"
    assert ch["version"] == "TLS1.2"
    # GREASE value 0x0A0A (2570) must be excluded from the JA3 string
    assert ch["ja3_str"] == "771,49195-49199,0-10-11,23,0"
    assert len(ch["ja3"]) == 32


def test_ja3_is_stable_and_sni_independent():
    a = parse_client_hello(build_hello("a.example"))
    b = parse_client_hello(build_hello("b.example"))
    assert a["ja3"] == b["ja3"]


def test_different_ciphers_change_ja3():
    a = parse_client_hello(build_hello("a.example"))
    b = parse_client_hello(build_hello("a.example", ciphers=(0xC02B,)))
    assert a["ja3"] != b["ja3"]


def test_non_tls_payload_returns_none():
    assert parse_client_hello(b"GET / HTTP/1.1\r\n\r\n") is None
    assert parse_client_hello(b"") is None
    assert parse_client_hello(b"\x16\x03\x01\x00\x05\x01") is None