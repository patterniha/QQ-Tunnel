import zlib


def get_crc32_bytes(data: bytes, chksum_pass: bytes) -> bytes:
    return zlib.crc32(data + chksum_pass).to_bytes(4, byteorder="big")


def compute_max_m(s: int, max_allowed: int) -> int:
    """
    Find maximum m such that: m + ⌈m / s⌉ ≤ max_allowed
    """
    if max_allowed <= 0:
        return 0

    q = max_allowed // (s + 1)
    remaining = max_allowed - q * (s + 1)
    r = max(0, remaining - 1)

    return q * s + r
