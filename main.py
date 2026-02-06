# todo: DNS(rd=1,qdcount=2,qd=DNSQR(qname="example.com", qtype="A") / DNSQR(qname="example.net", qtype="AAAA"))

import asyncio
import random
import socket
import json
import os
import sys

from scapy.compat import raw
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP

from utils import get_dns_query, get_base32_final_domains, extract_data_from_udp, \
    DATA_ID_WIDTH, \
    TOTAL_DATA_OFFSET
from data_handler import DataHandler
from utility.socket_tools import disable_udp_connreset
from utility.others import get_crc32_bytes
from utility.base32 import b32decode_nopad

BEGIN_SRC_PORT = 49152
END_SRC_PORT = 65534

Q_TYPE_STR = "A"
Q_TYPE_INT = 1

with open(os.path.join(os.path.dirname(sys.argv[0]), "config.json")) as f:
    config = json.loads(f.read())

interface_ip = config["interface_ip"]
dns_ips = config["dns_ips"]

outbound_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
outbound_socket.setblocking(False)
outbound_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 0)
outbound_socket.bind((interface_ip, 0))

h_inbound_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
h_inbound_socket.setblocking(False)
h_inbound_socket.bind((config["h_in_address"].rsplit(":", 1)[0], int(config["h_in_address"].rsplit(":", 1)[1])))

wan_inbound_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
wan_inbound_socket.setblocking(False)
if sys.platform == "win32":
    disable_udp_connreset(wan_inbound_socket)
wan_inbound_socket.bind((interface_ip, 53))

max_domain_len = config["max_domain_len"]
max_sub_len = config["max_sub_len"]
chksum_pass = str(config["chksum_pass"]).encode()
assemble_time = float(config["assemble_time"])
tries = config["retries"] + 1
recv_domain: str = config["recv_domain"]
send_domain: str = config["send_domain"]
if recv_domain[-1] == ".":
    recv_domain = recv_domain[:-1]
if send_domain[-1] == ".":
    send_domain = send_domain[:-1]

b_send_domain_lower = send_domain.lower().encode()
b_recv_domain_upper = recv_domain.upper().encode()

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
    data_offset = random.randint(0, TOTAL_DATA_OFFSET - 1)
    send_ip_index = random.randint(0, len(dns_ips) - 1)
    while True:
        if h_addr_is_fixed:
            raw_data = await loop.sock_recv(h_inbound_socket, 16384)
        else:
            raw_data, addr_h = await loop.sock_recvfrom(h_inbound_socket, 16384)
            if last_h_addr != addr_h:
                last_h_addr = addr_h
                print("the received data is sent to:", addr_h)

        if not raw_data:
            continue
        final_domains = get_base32_final_domains(raw_data, data_offset, b_send_domain_lower, max_domain_len,
                                                 max_sub_len, chksum_pass)
        if not final_domains:
            continue
        data_offset = (data_offset + 1) % TOTAL_DATA_OFFSET
        s_iter_send_ip_index = send_ip_index
        send_ip_index = (send_ip_index + tries) % len(dns_ips)
        for final_domain in final_domains:
            udp_dns = UDP(sport=src_port, dport=53) / get_dns_query(final_domain, query_id, Q_TYPE_STR)
            if src_port != END_SRC_PORT:
                src_port += 1
            else:
                src_port = BEGIN_SRC_PORT
            query_id = (query_id + 1) % 65536
            iter_send_ip_index = s_iter_send_ip_index
            curr_tries = tries
            while curr_tries > 0:
                send_ip = dns_ips[iter_send_ip_index]
                iter_send_ip_index = (iter_send_ip_index + 1) % len(dns_ips)
                ip_udp_dns = IP(src=interface_ip, dst=send_ip) / udp_dns
                data = raw(ip_udp_dns[UDP])
                await loop.sock_sendto(outbound_socket, data, (send_ip, 53))  # (send_ip, 0)
                curr_tries -= 1


async def wan_recv():
    loop = asyncio.get_running_loop()
    global max_domain_len
    global max_sub_len
    d_handler = DataHandler(TOTAL_DATA_OFFSET, assemble_time)
    while True:
        raw_data, addr_w = await loop.sock_recvfrom(wan_inbound_socket, 16384)
        if last_h_addr is not None:
            try:
                data_offset, fragment_part, last_fragment, chunk_data, query_id, query_qd = extract_data_from_udp(
                    raw_data,
                    b_recv_domain_upper,
                    DATA_ID_WIDTH, Q_TYPE_INT)
            except Exception as e:
                print("recv-error", e)
                continue

            response = raw(DNS(id=query_id, qr=1, rcode=3, qd=query_qd, aa=0))
            await loop.sock_sendto(wan_inbound_socket, response, addr_w)

            data = await d_handler.new_data_event(data_offset, fragment_part, last_fragment, chunk_data)
            if data:
                try:
                    data = b32decode_nopad(data)
                    final_data = data[:-4]
                    chksum = data[-4:]
                    assert final_data and len(chksum) == 4 and get_crc32_bytes(final_data, chksum_pass) == chksum
                except Exception as e:
                    print("data-error", e)
                    continue
                if h_addr_is_fixed:
                    await loop.sock_sendall(h_inbound_socket, final_data)
                else:
                    await loop.sock_sendto(h_inbound_socket, final_data, last_h_addr)


async def main():
    tw = asyncio.create_task(wan_recv())
    th = asyncio.create_task(h_recv())
    print("started...")
    await asyncio.wait([tw, th], return_when=asyncio.FIRST_COMPLETED)


asyncio.run(main())
