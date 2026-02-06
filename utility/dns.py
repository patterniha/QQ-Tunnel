from struct import pack

QTYPE_MAP = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12,
    "HINFO": 13, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33,
    "DS": 43, "DNSKEY": 48, "OPT": 41, "CAA": 257, "ANY": 255,
}

DNS_FLAG_RD = 0x0100  # recursion desired
DNS_QCLASS_IN = 0x0001


def encode_qname(domain: bytes) -> bytes:
    parts = [bytes((len(label),)) + label
             for label in domain.strip(b".").split(b".") if label]
    return b"".join(parts) + b"\x00"


def build_dns_query(qname_encoded: bytes, q_id: int, qtype: int) -> bytes:
    """
    qname_encoded: bytes with DNS label encoding (length-prefixed labels) ending with b'\\x00'
    q_id: 16-bit query ID
    qtype: 16-bit QTYPE (e.g., 1=A, 28=AAAA)
    """
    if not qname_encoded or qname_encoded[-1] != 0:
        raise ValueError("qname_encoded must end with a null byte (\\x00)")

    header = pack(
        "!HHHHHH",
        q_id & 0xFFFF,  # ID
        DNS_FLAG_RD,  # flags
        1,  # QDCOUNT
        0,  # ANCOUNT
        0,  # NSCOUNT
        0,  # ARCOUNT
    )

    question = qname_encoded + pack("!HH", qtype & 0xFFFF, DNS_QCLASS_IN)
    return header + question


def insert_dots(data: bytes, max_sub: int = 63) -> bytes:
    n = len(data)
    chunks = (n + max_sub - 1) // max_sub
    out = bytearray(n + chunks)

    out_i = 0
    for i in range(0, n, max_sub):
        seg = data[i:i + max_sub]
        out[out_i] = len(seg)
        out_i += 1
        out[out_i:out_i + len(seg)] = seg
        out_i += len(seg)

    return bytes(out)
