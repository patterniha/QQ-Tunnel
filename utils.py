import base64
import sys
from typing import Any

from scapy.layers.dns import DNS, DNSQR
from utility.base32 import BASE32_CHARS_LIST, BASE32_LOOKUP, base32_to_number, number_to_base32
from utility.others import get_crc32_bytes








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
        data_offset = data_offset_with_last & TOTAL_DATA_OFFSET_MINUS_ONE
        last_fragment = bool(data_offset_with_last >> DATA_OFFSET_MOVEMENT)
        fragment_part = BASE32_LOOKUP[o_f_d[offset_width]]
        if fragment_part < 0:
            raise ValueError("Invalid base32 character in fragment part")
        e_data = o_f_d[offset_width + 1:]
        if not e_data:
            raise ValueError("No data!")
        return data_offset, fragment_part, last_fragment, e_data, d.id, d.qd

    raise ValueError("Invalid data")
