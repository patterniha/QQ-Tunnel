from struct import pack_into, unpack_from

_DNS_HDR_LEN = 12
# QR=1, AA=1, RCODE=0 (NOERROR)
_NOERROR_FLAGS_BASE = 0x8400


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


def is_valid_request(data: bytes, qtype: int, encoded_domain: bytes) -> int:
    """
    Returns question_end (> 0) on valid request, 0 on invalid.
    """
    try:
        if len(data) < _DNS_HDR_LEN + 1:
            return 0

        flags, qdcount = unpack_from("!HH", data, 2)
        if flags & 0x8000:
            return 0
        if qdcount != 1:
            return 0

        qname_end = _skip_qname(data, _DNS_HDR_LEN)
        question_end = qname_end + 4

        if question_end > len(data):
            return 0

        if unpack_from("!H", data, qname_end)[0] != qtype:
            return 0

        if not data[_DNS_HDR_LEN:qname_end].lower().endswith(encoded_domain):
            return 0

        return question_end
    except Exception:
        return 0


def create_response(data: bytes, question_end: int) -> bytes:
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
