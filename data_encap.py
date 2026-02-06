import sys

from utility.base32 import b32encode_nopad_lower, BASE32_LIST_LOWER, number_to_base32_lower
from utility.others import get_crc32_bytes, compute_max_m
from utility.dns import insert_dots


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
    while c_loop:
        chunk_data = data[s_index:s_index + chunk_len]
        s_index += chunk_len
        if s_index < len(data):
            chunk_data = number_to_base32_lower(data_offset, data_offset_width) + BASE32_LIST_LOWER[i] + chunk_data
        else:
            chunk_data = number_to_base32_lower(data_offset | data_offset_nums, data_offset_width) + BASE32_LIST_LOWER[
                i] + chunk_data
            c_loop = False
        final_domain = insert_dots(chunk_data, max_sub_len) + qname_encoded
        if len(final_domain) > max_encoded_domain_len:
            sys.exit("Calculation Error!!!")
        final_b_domains.append(final_domain)
        i += 1

    return final_b_domains
