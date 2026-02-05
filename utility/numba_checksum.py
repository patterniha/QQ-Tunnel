from numba import njit, uint64


@njit(cache=True, fastmath=True)
def checksum_numba(data, length):
    s = uint64(0)
    i = 0
    n = length & ~1  # even length

    # process 2‑byte words
    while i < n:
        s += (uint64(data[i]) << 8) | uint64(data[i + 1])
        i += 2

    # odd tail
    if length & 1:
        s += uint64(data[n]) << 8

    # fold to 16 bits
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)

    return (~s) & 0xFFFF


def checksum(data: bytes) -> int:
    return int(checksum_numba(data, len(data)))
