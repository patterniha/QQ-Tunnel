import zlib


def get_crc32_bytes(data: bytes, chksum_pass: bytes) -> bytes:
    return zlib.crc32(data + chksum_pass).to_bytes(4, byteorder="big")
