import base64
import sys
from typing import Any

from scapy.layers.dns import DNS, DNSQR
from utility.base32 import BASE32_CHARS_LIST, BASE32_LOOKUP, base32_to_number, number_to_base32
from utility.others import get_chksum

DATA_ID_WIDTH = 4
DATA_OFFSET_MOVEMENT = 5 * DATA_ID_WIDTH - 1
TOTAL_DATA_OFFSET = 1 << DATA_OFFSET_MOVEMENT
NOT_TOTAL_DATA_OFFSET = ~TOTAL_DATA_OFFSET


def get_dns_query(final_domain: bytes, q_id: int, qtype: str):
    return DNS(rd=1, id=q_id, qd=DNSQR(qname=final_domain, qtype=qtype))


def insert_dots(data: bytes, max_sub=63) -> bytes:
    ret = b""
    while data:
        ret += data[:max_sub]
        data = data[max_sub:]
        ret += b"."

    return ret


def get_base32_final_domains(data: bytes, data_offset: int, b_domain_lower: bytes, max_domain_len: int, max_sub: int,
                             chksum_pass: bytes) -> \
        list[bytes]:
    data += get_chksum(data, chksum_pass)
    data = base64.b32encode(data).rstrip(b"=")
    l1 = max_domain_len - len(b_domain_lower) - 1
    num_added_dots = l1 // (max_sub + 1)
    chunk_len = l1 - num_added_dots - DATA_ID_WIDTH - 1
    if (len(data) + chunk_len - 1) // chunk_len > 32:
        print("ERROR: max_domain_len is too small, packet is not sent, len:", len(data))
        return []
    final_b_domains = []
    i = 0
    c_loop = True
    while c_loop:
        b32_t = data[:chunk_len]
        data = data[chunk_len:]
        if data:
            b32_t = number_to_base32(data_offset, DATA_ID_WIDTH) + BASE32_CHARS_LIST[i] + b32_t
        else:
            b32_t = number_to_base32(data_offset | TOTAL_DATA_OFFSET, DATA_ID_WIDTH) + BASE32_CHARS_LIST[
                i] + b32_t
            c_loop = False
        final_domain = insert_dots(b32_t, max_sub).lower() + b_domain_lower
        if len(final_domain) > max_domain_len:
            sys.exit("DEBUG ERROR: Calculation error")
        final_b_domains.append(final_domain)
        i += 1

    return final_b_domains


def extract_data_from_udp(raw_bytes: bytes, b_domain_upper: bytes, offset_width: int, qtype_int: int) -> tuple[
    int, int, bool, bytes, Any, Any]:
    d = DNS(raw_bytes)
    if d.qr != 0:
        raise ValueError("no request!")
    if d.qd.qtype != qtype_int:
        raise ValueError("invalid qtype!")
    b_final_domain: bytes = d.qd.qname.rstrip(b".").upper()

    if b_final_domain.endswith(b"." + b_domain_upper):
        # domain_len = len(b_final_domain)
        # first_sub_len = b_final_domain.find(b".")
        o_f_d = b_final_domain[:-len(b_domain_upper) - 1]
        o_f_d = o_f_d.replace(b".", b"")
        data_offset_with_last = base32_to_number(o_f_d[:offset_width])
        data_offset = data_offset_with_last & NOT_TOTAL_DATA_OFFSET
        last_fragment = bool(data_offset_with_last >> DATA_OFFSET_MOVEMENT)
        fragment_part = BASE32_LOOKUP[o_f_d[offset_width]]
        if fragment_part < 0:
            raise ValueError("Invalid base32 character in fragment part")
        e_data = o_f_d[offset_width + 1:]
        if not e_data:
            raise ValueError("No data!")
        return data_offset, fragment_part, last_fragment, e_data, d.id, d.qd

    raise ValueError("Invalid data")
