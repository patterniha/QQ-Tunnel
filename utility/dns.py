from struct import pack

DNS_FLAG_RD = 0x0100  # recursion desired
DNS_QCLASS_IN = 0x0001


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


def encode_qname(domain: bytes) -> bytes:
    parts = [bytes((len(label),)) + label
             for label in domain.strip(b".").split(b".") if label]
    return b"".join(parts) + b"\x00"
