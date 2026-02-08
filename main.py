# todo: DNS(rd=1,qdcount=2,qd=DNSQR(qname="example.com", qtype="A") / DNSQR(qname="example.net", qtype="AAAA"))
# todo: test ips

import asyncio
import random
import socket
import json
import os
import sys

from data_handler import DataHandler
from utility.socket_tools import disable_udp_connreset
from utility.base32 import b32decode_nopad
from utility.dns import QTYPE_MAP, label_domain, encode_qname, build_dns_query, handle_dns_request, \
    create_noerror_empty_response
from data_cap import get_crc32_bytes, get_base32_final_domains, get_chunk_len, get_chunk_data
from utility.packets import build_udp_payload_v4

BEGIN_SRC_PORT = 49152
END_SRC_PORT = 65534

Q_TYPE = "A"

DATA_OFFSET_WIDTH = 4

##############################
TOTAL_DATA_OFFSET = 1 << 5 * DATA_OFFSET_WIDTH
TOTAL_DATA_OFFSET_MINUS_ONE = TOTAL_DATA_OFFSET - 1
Q_TYPE_INT = QTYPE_MAP[Q_TYPE]

with open(os.path.join(os.path.dirname(sys.argv[0]), "config.json")) as f:
    config = json.loads(f.read())

send_interface_ip_str = config["send_interface_ip"]
send_interface_ip = socket.inet_pton(socket.AF_INET, send_interface_ip_str)
send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
send_socket.setblocking(False)
send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 0)
send_socket.bind((send_interface_ip_str, 0))

receive_interface_ip_str = config["receive_interface_ip"]
receive_interface_ip = socket.inet_pton(socket.AF_INET, receive_interface_ip_str)
receive_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
receive_socket.setblocking(False)
if sys.platform == "win32":
    disable_udp_connreset(receive_socket)
receive_socket.bind((receive_interface_ip_str, 53))

dns_ips = [(ip_str, socket.inet_pton(socket.AF_INET, ip_str)) for ip_str in config["dns_ips"]]

h_inbound_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
h_inbound_socket.setblocking(False)
if sys.platform == "win32":
    disable_udp_connreset(h_inbound_socket)
h_inbound_socket.bind((config["h_in_address"].rsplit(":", 1)[0], int(config["h_in_address"].rsplit(":", 1)[1])))

max_encoded_domain_len = config["max_domain_len"] + 2
if max_encoded_domain_len > 255:
    sys.exit("the maximum domain length is 253 bytes")
max_sub_len = config["max_sub_len"]
if max_sub_len > 63:
    sys.exit("max_sub_len cannot be greater than 63!")
chksum_pass = config["chksum_pass"].encode()
assemble_time = float(config["assemble_time"])
tries = config["retries"] + 1
recv_domain_labels = label_domain(config["recv_domain"].encode().lower())
len_recv_domain_labels = len(recv_domain_labels)
send_domain_encode_qname = encode_qname(config["send_domain"].encode().lower())
chunk_len = get_chunk_len(max_encoded_domain_len, len(send_domain_encode_qname), max_sub_len, DATA_OFFSET_WIDTH)

if config["h_out_address"]:
    last_h_addr = (config["h_out_address"].rsplit(":", 1)[0], int(config["h_out_address"].rsplit(":", 1)[1]))
    h_addr_is_fixed = True
    h_inbound_socket.connect(last_h_addr)
else:
    last_h_addr = None
    h_addr_is_fixed = False


async def h_recv():
    loop = asyncio.get_running_loop()
    global last_h_addr
    src_port = random.randint(BEGIN_SRC_PORT, END_SRC_PORT)
    query_id = random.randint(0, 65535)
    data_offset = random.randint(0, TOTAL_DATA_OFFSET_MINUS_ONE)
    send_ip_index = random.randint(0, len(dns_ips) - 1)
    while True:
        if h_addr_is_fixed:
            raw_data = await loop.sock_recv(h_inbound_socket, 4096)
        else:
            raw_data, addr_h = await loop.sock_recvfrom(h_inbound_socket, 4096)
            if last_h_addr != addr_h:
                last_h_addr = addr_h
                print("the received data is sent to:", addr_h)

        if not raw_data:
            continue
        final_domains = get_base32_final_domains(raw_data, data_offset, chunk_len, send_domain_encode_qname,
                                                 max_sub_len, chksum_pass, DATA_OFFSET_WIDTH, max_encoded_domain_len)
        if not final_domains:
            continue
        data_offset = (data_offset + 1) & TOTAL_DATA_OFFSET_MINUS_ONE
        s_iter_send_ip_index = send_ip_index
        send_ip_index = (send_ip_index + tries) % len(dns_ips)
        for final_domain in final_domains:
            use_src_port = src_port
            use_query_id = query_id
            if src_port != END_SRC_PORT:
                src_port += 1
            else:
                src_port = BEGIN_SRC_PORT
            query_id = (query_id + 1) & 0xFFFF
            iter_send_ip_index = s_iter_send_ip_index
            curr_tries = tries
            while curr_tries > 0:
                send_ip_str, send_ip = dns_ips[iter_send_ip_index]
                iter_send_ip_index = (iter_send_ip_index + 1) % len(dns_ips)
                data = build_udp_payload_v4(build_dns_query(final_domain, use_query_id, Q_TYPE_INT), use_src_port, 53,
                                            send_interface_ip, send_ip)
                await loop.sock_sendto(send_socket, data, (send_ip_str, 53))  # (send_ip_str, 0)
                curr_tries -= 1


async def wan_recv():
    loop = asyncio.get_running_loop()
    d_handler = DataHandler(TOTAL_DATA_OFFSET, assemble_time)
    while True:
        raw_data, addr_w = await loop.sock_recvfrom(receive_socket, 4096)
        if last_h_addr is not None:
            try:
                qid, qflags, all_labels, qtype, next_question = handle_dns_request(raw_data)
                if qtype != Q_TYPE_INT:
                    raise ValueError("invalid qtype!")
                domain_labels = all_labels[-len_recv_domain_labels:]
                assert [label.lower() for label in domain_labels] == recv_domain_labels
                data_with_header = b"".join(all_labels[:-len_recv_domain_labels])
                if not data_with_header:
                    raise ValueError("no header")
                data_offset, fragment_part, last_fragment, chunk_data = get_chunk_data(data_with_header,
                                                                                       DATA_OFFSET_WIDTH)
                if not chunk_data:
                    raise ValueError("no chunk data")
                if fragment_part == 63 and not last_fragment:
                    raise ValueError("last possible fragment part but not last fragment")
            except Exception as e:
                print("recv-error", e)
                continue

            data = await d_handler.new_data_event(data_offset, fragment_part, last_fragment, chunk_data)
            if data:
                try:
                    data = b32decode_nopad(data)
                    final_data = data[:-4]
                    chksum = data[-4:]
                    assert final_data and len(chksum) == 4 and get_crc32_bytes(final_data, chksum_pass) == chksum
                except Exception as e:
                    print("data-error", e)
                else:
                    if h_addr_is_fixed:
                        await loop.sock_sendall(h_inbound_socket, final_data)
                    else:
                        await loop.sock_sendto(h_inbound_socket, final_data, last_h_addr)

            response = create_noerror_empty_response(qid, qflags, raw_data[12:next_question])
            await loop.sock_sendto(receive_socket, response, addr_w)


async def main():
    tw = asyncio.create_task(wan_recv())
    th = asyncio.create_task(h_recv())
    print("started...")
    await asyncio.wait([tw, th], return_when=asyncio.FIRST_COMPLETED)


asyncio.run(main())
