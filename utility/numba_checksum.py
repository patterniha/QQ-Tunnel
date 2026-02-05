from numba import njit, uint64


@njit(cache=True, fastmath=True)
def checksum_numba_fastest(data, length):
    s = uint64(0)
    i = 0
    n = length & ~1  # even length

    # unroll 8 bytes at a time
    n8 = n & ~7
    while i < n8:
        s += (uint64(data[i]) << 8) | uint64(data[i + 1])
        s += (uint64(data[i + 2]) << 8) | uint64(data[i + 3])
        s += (uint64(data[i + 4]) << 8) | uint64(data[i + 5])
        s += (uint64(data[i + 6]) << 8) | uint64(data[i + 7])
        i += 8

    # remaining 2‑byte words
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
    return int(checksum_numba_fastest(data, len(data)))
