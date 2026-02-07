from struct import pack_into, unpack_from

_DNS_HDR_LEN = 12
# QR=1, AA=1, RCODE=0 (NOERROR)
_NOERROR_FLAGS_BASE = 0x8400
_NOERROR_FLAGS_BASE_RD = 0x8500


def _skip_qname(data: bytes, offset: int) -> int:
    n = len(data)
    while offset < n:
        label_len = data[offset]
        if label_len == 0:
            return offset + 1
        if label_len > 63:
            raise ValueError
        offset += 1 + label_len
        if offset >= n:
            raise ValueError
    raise ValueError


def handle_dns_request(data: bytes) -> tuple[int, int, bytes, int, bytes, int]:
    if len(data) < _DNS_HDR_LEN + 1:
        raise ValueError

    flags, qdcount = unpack_from("!HH", data, 2)
    if flags & 0x8000:
        raise ValueError("not query")
    if qdcount != 1:
        raise ValueError("not 1 question")

    qname_end = _skip_qname(data, _DNS_HDR_LEN)
    question_end = qname_end + 4

    if question_end > len(data):
        raise ValueError

    qid = unpack_from("!H", data, 0)[0]
    qtype = unpack_from("!H", data, qname_end)[0]
    qclass = unpack_from("!H", data, qname_end + 2)[0]
    if qclass != 1:
        raise ValueError("invalid question class")
    qname = data[_DNS_HDR_LEN:qname_end]

    return qid, qtype, qname, question_end, data[_DNS_HDR_LEN:question_end], bool(data[2] & 0X01)


def create_response(...) -> bytes:
    """
    Build NOERROR empty response. Call only after is_valid_request returns > 0.
    """
    resp = bytearray(question_end)
    resp[_DNS_HDR_LEN:] = data[_DNS_HDR_LEN:question_end]

    pack_into(
        "!HHHHHH", resp, 0,
        unpack_from("!H", data, 0)[0],  # ID
        _NOERROR_FLAGS_BASE | (data[2] & 0x01) << 8,  # preserve RD
        1,  # QDCOUNT
        0,  # ANCOUNT
        0,  # NSCOUNT
        0,  # ARCOUNT
    )

    return bytes(resp)
