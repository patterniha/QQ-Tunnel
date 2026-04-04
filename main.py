# todo: DNS(rd=1,qdcount=2,qd=DNSQR(qname="example.com", qtype="A") / DNSQR(qname="example.net", qtype="AAAA"))
# todo: test ips

import asyncio
import random
import socket
import json
import os
import sys

from data_handler import DataHandler
from utility.base32 import b32decode_nopad
from utility.dns import label_domain, encode_qname, build_dns_query, handle_dns_request, \
    create_noerror_empty_response
from data_cap import get_crc32_bytes, get_base32_final_domains, get_chunk_len, get_chunk_data

PACKETS_QUEUE_SIZE = 1024

ASSEMBLE_TIME = 10.0

DATA_OFFSET_WIDTH = 4

TOTAL_DATA_OFFSET = 1 << 5 * DATA_OFFSET_WIDTH
TOTAL_DATA_OFFSET_MINUS_ONE = TOTAL_DATA_OFFSET - 1


def create_v4_udp_dgram_socket(blocking: bool, bind_addr: None | tuple) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(blocking)
    if bind_addr is not None:
        s.bind(bind_addr)
    return s


with open(os.path.join(os.path.dirname(sys.argv[0]), "config.json")) as f:
    config = json.loads(f.read())

send_query_type_int = config["send_query_type_int"]
recv_query_type_int = config["recv_query_type_int"]

send_interface_ip_str = config["send_interface_ip"]
send_sock_list = []
# ulimit -n 32768
for _ in range(config["send_sock_numbers"]):
    send_sock_list.append(create_v4_udp_dgram_socket(False, (send_interface_ip_str, 0)))

wan_receive_bind_addr = (config["receive_interface_ip"], int(config["receive_port"]))

dns_ips = config["dns_ips"]
queues_list: list[asyncio.Queue] = []

h_inbound_bind_addr = (config["h_in_address"].rsplit(":", 1)[0], int(config["h_in_address"].rsplit(":", 1)[1]))
h_inbound_socket = create_v4_udp_dgram_socket(False, h_inbound_bind_addr)

max_encoded_domain_len = config["max_domain_len"] + 2
if max_encoded_domain_len > 255:
    sys.exit("the maximum domain length is 253 bytes")
max_sub_len = config["max_sub_len"]
if max_sub_len > 63:
    sys.exit("max_sub_len cannot be greater than 63!")
chksum_pass = config["chksum_pass"].encode()
tries = config["retries"] + 1
all_recv_domains_labels = []
for recv_domain in config["recv_domains"]:
    all_recv_domains_labels.append(label_domain(recv_domain.encode().lower()))

send_domain_encode_qname = encode_qname(config["send_domain"].encode().lower())
chunk_len = get_chunk_len(max_encoded_domain_len, len(send_domain_encode_qname), max_sub_len, DATA_OFFSET_WIDTH)

use_fixed_h_addr = False
last_h_addr = None
if config["h_out_address"]:
    last_h_addr = (config["h_out_address"].rsplit(":", 1)[0], int(config["h_out_address"].rsplit(":", 1)[1]))
    use_fixed_h_addr = True


async def wan_send_from_queue(queue: asyncio.Queue):
    loop = asyncio.get_running_loop()
    while True:
        send_socks_datas, send_ip_str, entry_time, curr_try = await queue.get()
        if loop.time() - entry_time > 1:
            continue  # drop

        if curr_try & 1 == 0:
            iter_range = range(len(send_socks_datas))
        else:
            iter_range = range(len(send_socks_datas) - 1, -1, -1)

        for i in iter_range:
            send_sock_index, send_sock, data = send_socks_datas[i]
            try:
                await loop.sock_sendto(send_sock, data, (send_ip_str, 53))
            except Exception as e:
                print("wan_send_sock send error:", e, send_ip_str, send_sock)
                send_sock.close()
                while True:
                    await asyncio.sleep(1)
                    if send_sock_list[send_sock_index] != send_sock:
                        break
                    try:
                        send_sock_list[send_sock_index] = create_v4_udp_dgram_socket(False, (send_interface_ip_str, 0))
                    except Exception as e:
                        print("wan_send_sock create error:", e)
                        continue
                    break
                break
            await asyncio.sleep(0.0000001)


async def h_recv():
    loop = asyncio.get_running_loop()
    global h_inbound_socket
    global last_h_addr
    send_sock_index = random.randint(0, len(send_sock_list) - 1)
    query_id = random.randint(0, 65535)
    data_offset = random.randint(0, TOTAL_DATA_OFFSET_MINUS_ONE)
    send_ip_index = random.randint(0, len(dns_ips) - 1)
    queue_index = random.randint(0, len(queues_list) - 1)
    while True:
        use_h_inbound_socket = h_inbound_socket
        try:
            raw_data, addr_h = await loop.sock_recvfrom(use_h_inbound_socket, 65575)
            if not addr_h:
                raise ValueError("h inbound socket no addr!")
        except Exception as e:
            print("h_inbound_socket recv error:", e)
            use_h_inbound_socket.close()
            while True:
                if h_inbound_socket != use_h_inbound_socket:
                    break
                try:
                    h_inbound_socket = create_v4_udp_dgram_socket(False, h_inbound_bind_addr)
                except Exception as e:
                    print("h_inbound_socket create error:", e)
                    await asyncio.sleep(1)
                    continue
                break
            continue

        if use_fixed_h_addr:
            if addr_h != last_h_addr:
                continue
        elif last_h_addr != addr_h:
            last_h_addr = addr_h
            print("the received data is sent to:", addr_h)

        if not raw_data:
            continue
        final_domains = get_base32_final_domains(raw_data, data_offset, chunk_len, send_domain_encode_qname,
                                                 max_sub_len, chksum_pass, DATA_OFFSET_WIDTH, max_encoded_domain_len)
        if not final_domains:
            continue
        data_offset = (data_offset + 1) & TOTAL_DATA_OFFSET_MINUS_ONE
        send_socks_datas = []
        for final_domain in final_domains:
            send_socks_datas.append(
                (send_sock_index, send_sock_list[send_sock_index],
                 build_dns_query(final_domain, query_id, send_query_type_int)))
            send_sock_index = (send_sock_index + 1) % len(send_sock_list)
            query_id = (query_id + 1) & 0xFFFF

        curr_try = 0
        while curr_try < tries:
            try:
                queues_list[queue_index].put_nowait((send_socks_datas, dns_ips[send_ip_index], loop.time(), curr_try))
            except asyncio.QueueFull:
                pass
            send_ip_index = (send_ip_index + 1) % len(dns_ips)
            queue_index = (queue_index + 1) % len(queues_list)
            curr_try += 1


async def wan_recv():
    loop = asyncio.get_running_loop()
    global h_inbound_socket
    wan_receive_socket = create_v4_udp_dgram_socket(False, wan_receive_bind_addr)
    d_handler = DataHandler(TOTAL_DATA_OFFSET, ASSEMBLE_TIME)
    while True:
        try:
            raw_data, addr_w = await loop.sock_recvfrom(wan_receive_socket, 65575)
            if not addr_w:
                raise ValueError("wan receive socket no addr!")
        except Exception as e:
            # print("wan receive socket recv error:", e)
            wan_receive_socket.close()
            while True:
                try:
                    wan_receive_socket = create_v4_udp_dgram_socket(False, wan_receive_bind_addr)
                except Exception as e:
                    print("wan receive socket create error:", e)
                    await asyncio.sleep(1)
                    continue
                break
            continue

        try:
            qid, qflags, all_labels, qtype, next_question = handle_dns_request(raw_data)
            if qtype != recv_query_type_int:
                raise ValueError("invalid qtype!")

            accepted_recv_domain_labels_len = 0
            for recv_domain_labels in all_recv_domains_labels:
                len_recv_domain_labels = len(recv_domain_labels)
                if all_labels[-len_recv_domain_labels:] == recv_domain_labels:
                    accepted_recv_domain_labels_len = len_recv_domain_labels
                    break
            if accepted_recv_domain_labels_len == 0:
                raise ValueError("no accepted recv_domain_labels")


        except Exception as e:
            print("receive invalid request:", raw_data)
            continue

        try:
            if last_h_addr is None:
                raise ValueError("no last_h_addr")
            data_with_header = b"".join(all_labels[:-accepted_recv_domain_labels_len])
            if not data_with_header:
                raise ValueError("no header")
            data_offset, fragment_part, last_fragment, chunk_data = get_chunk_data(data_with_header,
                                                                                   DATA_OFFSET_WIDTH)
            if not chunk_data:
                raise ValueError("no chunk data")
            if fragment_part == 63 and not last_fragment:
                raise ValueError("last possible fragment part but not last fragment")
        except Exception as e:
            # print("error when extracting data", e)
            pass
        else:
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
                    use_h_inbound_socket = h_inbound_socket
                    try:
                        await loop.sock_sendto(use_h_inbound_socket, final_data, last_h_addr)
                    except Exception as e:
                        print("h_inbound_socket send error:", e)
                        use_h_inbound_socket.close()
                        while True:
                            if h_inbound_socket != use_h_inbound_socket:
                                break
                            try:
                                h_inbound_socket = create_v4_udp_dgram_socket(False, h_inbound_bind_addr)
                            except Exception as e:
                                print("h_inbound_socket create error:", e)
                                await asyncio.sleep(1)
                                continue
                            break

        response = create_noerror_empty_response(qid, qflags, raw_data[12:next_question])
        try:
            await loop.sock_sendto(wan_receive_socket, response, addr_w)
        except Exception as e:
            print("wan receive socket send error:", e)
            wan_receive_socket.close()
            while True:
                try:
                    wan_receive_socket = create_v4_udp_dgram_socket(False, wan_receive_bind_addr)
                except Exception as e:
                    print("wan receive socket create error:", e)
                    await asyncio.sleep(1)
                    continue
                break


async def main():
    wait_list = []
    for _ in dns_ips:
        queue = asyncio.Queue(maxsize=PACKETS_QUEUE_SIZE)
        queues_list.append(queue)
        wait_list.append(asyncio.create_task(wan_send_from_queue(queue)))

    wait_list.append(asyncio.create_task(h_recv()))
    wait_list.append(asyncio.create_task(wan_recv()))
    print("started...")
    await asyncio.wait(wait_list, return_when=asyncio.FIRST_COMPLETED)


asyncio.run(main())
