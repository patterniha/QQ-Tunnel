import sys
import zlib

from utility.base32 import b32encode_nopad_lower, BASE32_LIST_LOWER, number_to_base32_lower, base32_to_number, \
    BASE32_LOOKUP
from utility.dns import insert_dots


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


def get_chunk_len(max_encoded_domain_len: int, qname_encoded_len: int, max_sub_len: int, data_offset_width=4) -> int:
    max_allowed = max_encoded_domain_len - qname_encoded_len
    m = compute_max_m(max_sub_len, max_allowed)
    chunk_len = m - data_offset_width - 1  # fragment_part_width is 1
    if chunk_len <= 0:
        raise ValueError("max_encoded_domain_len is too small to fit any data")
    return chunk_len


def get_base32_final_domains(data: bytes, data_offset: int, chunk_len: int, qname_encoded: bytes, max_sub_len: int,
                             chksum_pass: bytes, data_offset_width: int, data_offset_nums: int,
                             max_encoded_domain_len: int) -> \
        list[bytes]:
    data = b32encode_nopad_lower(data + get_crc32_bytes(data, chksum_pass))
    if (len(data) + chunk_len - 1) // chunk_len > 32:
        print("ERROR: max_domain_len is too small, packet is not sent, len:", len(data))
        return []
    final_b_domains = []
    i = 0
    c_loop = True
    s_index = 0
    prefix_normal = number_to_base32_lower(data_offset, data_offset_width)
    prefix_last = number_to_base32_lower(data_offset | data_offset_nums, data_offset_width)
    len_data = len(data)
    while c_loop:
        chunk_data = data[s_index:s_index + chunk_len]
        s_index += chunk_len
        if s_index < len_data:
            chunk_data = b"".join((prefix_normal, BASE32_LIST_LOWER[i], chunk_data))
        else:
            chunk_data = b"".join((prefix_last, BASE32_LIST_LOWER[i], chunk_data))
            c_loop = False
        final_domain = insert_dots(chunk_data, max_sub_len) + qname_encoded
        if len(final_domain) > max_encoded_domain_len:
            sys.exit("Calculation Error!!!")
        final_b_domains.append(final_domain)
        i += 1

    return final_b_domains


def get_chunk_data(data, data_offset_width: int, total_data_offset_minus_one: int, data_offset_movement: int):
    data_offset_with_last = base32_to_number(data[:data_offset_width])
    data_offset = data_offset_with_last & total_data_offset_minus_one
    last_fragment = bool(data_offset_with_last >> data_offset_movement)
    fragment_part = BASE32_LOOKUP[data[data_offset_width]]
    if fragment_part < 0:
        raise ValueError("Invalid base32 character in fragment part")
    e_data = data[data_offset_width + 1:]
    return data_offset, fragment_part, last_fragment, e_data
