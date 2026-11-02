#!/usr/bin/env python3
"""RFC 0033 e2e: a minimal IPv4 MaxMind DB on stdout, as test_db in
crates/l7/src/intel/geoip.rs writes it. Every argument maps one network to
a country and an ASN; use RFC 5737 ranges and private ASNs.

  geoip-db.py 192.0.2.0/24=XA/64512 > test.mmdb
"""

import ipaddress
import sys


def control(out, kind, size):
    assert size < 29
    out += bytes([kind << 5 | size]) if kind <= 7 else bytes([size, kind - 7])


def string(out, s):
    control(out, 2, len(s))
    out += s.encode()


def uint(out, kind, v):
    b = v.to_bytes(8, "big").lstrip(b"\0")
    control(out, kind, len(b))
    out += b


def db(entries):
    nodes, data = [[None, None]], bytearray()
    for net, cc, asn in entries:
        off = len(data)
        control(data, 7, 2)
        string(data, "country")
        control(data, 7, 1)
        string(data, "iso_code")
        string(data, cc)
        string(data, "autonomous_system_number")
        uint(data, 6, asn)
        bits, node = int(net.network_address), 0
        for i in range(net.prefixlen):
            bit = bits >> (31 - i) & 1
            if i + 1 == net.prefixlen:
                nodes[node][bit] = ("data", off)
            elif isinstance(nodes[node][bit], int):
                node = nodes[node][bit]
            else:
                nodes.append([None, None])
                nodes[node][bit] = len(nodes) - 1
                node = len(nodes) - 1
    count, out = len(nodes), bytearray()
    for rec in (r for n in nodes for r in n):
        v = count if rec is None else rec if isinstance(rec, int) else count + 16 + rec[1]
        out += v.to_bytes(3, "big")
    out += bytes(16) + data + b"\xab\xcd\xefMaxMind.com"
    control(out, 7, 9)
    for k in ("binary_format_major_version", "binary_format_minor_version"):
        string(out, k)
        uint(out, 5, 2 if "major" in k else 0)
    string(out, "build_epoch")
    uint(out, 9, 0)
    string(out, "database_type")
    string(out, "Dvarapala-Test")
    string(out, "description")
    control(out, 7, 1)
    string(out, "en")
    string(out, "test")
    string(out, "ip_version")
    uint(out, 5, 4)
    string(out, "languages")
    control(out, 11, 1)
    string(out, "en")
    string(out, "node_count")
    uint(out, 6, count)
    string(out, "record_size")
    uint(out, 5, 24)
    return bytes(out)


def entry(arg):
    net, rest = arg.split("=")
    cc, asn = rest.split("/")
    return ipaddress.IPv4Network(net), cc, int(asn)


if __name__ == "__main__":
    sys.stdout.buffer.write(db([entry(a) for a in sys.argv[1:]]))
