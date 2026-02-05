import base64

BASE32_CHARS_LIST = [b"A", b"B", b"C", b"D", b"E", b"F", b"G", b"H", b"I", b"J", b"K", b"L", b"M", b"N", b"O", b"P",
                     b"Q", b"R", b"S", b"T", b"U", b"V", b"W", b"X", b"Y", b"Z", b"2", b"3", b"4", b"5", b"6", b"7"]

BASE32_CHARS_BYTES = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

# Precompute lookup table for byte -> value (or -1 if invalid)
_BASE32_LOOKUP = [-1] * 256
for i, ch in enumerate(BASE32_CHARS_BYTES):
    _BASE32_LOOKUP[ch] = i


def number_to_base32(n: int, width: int) -> bytes:
    result = bytearray(width)
    for i in range(width - 1, -1, -1):
        n, remainder = divmod(n, 32)
        result[i] = BASE32_CHARS_BYTES[remainder]
    return bytes(result)


def base32_to_number(s: bytes) -> int:
    value = 0
    for ch in s:
        idx = _BASE32_LOOKUP[ch]
        if idx < 0:
            raise ValueError(f"Invalid base32 character: {ch}")
        value = value * 32 + idx
    return value


def b32decode_nopad(s: bytes) -> bytes:
    pad = (-len(s)) % 8
    return base64.b32decode(s + b"=" * pad, casefold=True)


def b32encode_nopad(s: bytes) -> bytes:
    return base64.b32encode(s).rstrip(b"=")
