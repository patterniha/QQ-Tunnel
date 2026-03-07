# QQ-Tunnel
Sending and receiving data both with dns query

# How does it work?
Receive data from a UDP socket and embed it to domains of DNS-Qurey.
If needed, it splits the data into multiple parts and then merges them on the other side.
So for accessing internet, you need a reliable data transfer over UDP like: wireguard/hysteria/kcp/...

# DNS records
you need to set 4 DNS records for your domain:

a.example.com A server-1-ip

na.example.com NS a.example.com

b.example.com A server-2-ip

nb.example.com NS b.example.com

# How to config?

dns_ips: list of dns resolvers, you can use multiple resolvers and each time one of them is choosen for sending data (round robin). Be careful, although choosing multiple resolvers improves performance, but if one of them is broken, the tunnel will be disrupted.

send_interface_ip: interface ip that use for sending data, usually your server ip, or if you are behind nat, this is your nat ip.
recv_interface_ip: interface ip that use for receiving data, usually your server ip, or if you are behind nat, this is your nat ip.

recveive_port: the port that use for receiving DNS-Query

send_domain: the domain that point to other server, for example for server-1 this is nb.example.com
recv_domain: the domain that you expect to receive, this is other side send_domain, so for example for server-1 this is na.example.com

h_in_address: UDP listen address that receive data from hysteria/kcp/wireguard..., in the server that you run hysteria/kcp/wireguard/... client you should set this address as endpoint (target address) in your hysteria/kcp/wireguard/... client config, and in the other side that run hysteria/kcp/wireguard/... server, this address port is not important and you can choose any port.

h_out_address: set it only on the side that you run hysteria/kcp/wireguard/... server, and this the address that hysteria/kcp/wireguard/... server that listen to, in the other side that run hysteria/kcp/wireguard/... client leave it empty (in client side h_out_address automatically is set to the last address that receive data from)

max_domain_len: maximum length of final domain length that resolver allow to pass, (count without trailing dot, for example the length of a.b.com is 7), in theory, resolvers should support up to 253 domain length, but some resolvers limited to lower value (99/151/...)

max_sub_len: maximum length of each subdomain-part (parts between two dots), in theory, resolvers should support up to 63 for each part.

retries: nubmer of retries, for example if set to 2, each data is send 3 times.all tries is sent immediately, so if you set it to 2, your bandwidth usage is multiplied by 3, because received data usually needs to split into parts, and we may have packet lost for some parts, this option help to reduce packet lost, but increase bandwidth usage (hysteria/kcp/wireguard/... retransmit data if they don't receive it's ACK, so you usually don't need this option)

send_query_type_int: integer query type of sending DNS-Query ("A": 1, "AAAA": 28, "TXT": 16,...)
recv_query_type_int: integer query type of DNS-Query that you expect to receive, this is other side send_query_type_int

send_sock_numbers: number of udp sockets that use for sending data, for bypassing resolvers rate limit, it is better to send data with different source ports (so we use multiple sockets with different source port to send data), you may need to run "ulimit -n 32768" to increase limit of number of file descriptors.

assemble_time: data may need to splits into parts, and send in multiple DNS-Query, the other side buffer the parts and after all parts of each data is received, it merge them and then send it to kcp/wireguard/hysteria..., this is the timeout for waiting for other parts when the first part is received.






