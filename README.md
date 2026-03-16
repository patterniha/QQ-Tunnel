# QQ-Tunnel

Sending and receiving data both with dns query

# How does it work?

It receives data from a UDP listener and embeds it in domains of DNS-Qurey and send.

If needed, it splits the data into multiple parts and then merges them on the other side.

It just acts as a UDP forwarder, so for accessing internet, you need a reliable data transfer over UDP like:
wireguard/hysteria/kcp/...

# DNS records

you need to set 4 DNS records for your domain:

`a.example.com A server-1-ip`

`na.example.com NS a.example.com`

`b.example.com A server-2-ip`

`nb.example.com NS b.example.com`

# How to config?

`dns_ips`: list of dns resolvers, you can use multiple resolvers and each time one of them is choosen for sending data (
round robin). Be careful, although choosing multiple resolvers improves performance, but if one of them is broken, the
tunnel will be disrupted.

`send_interface_ip`: interface ip that use for sending data, usually your server ip, or if you are behind nat, this is
your nat ip.

`recv_interface_ip`: interface ip that use for receiving data, usually your server ip, or if you are behind nat, this is
your nat ip.

`recveive_port`: the port that use for receiving DNS-Query, the prerouting received port is always 53.

`send_domain`: the domain that point to other server, for example for server-1 this is nb.example.com

`recv_domain`: the domain that you expect to receive, this is other side send_domain, so for example for server-1 this
is na.example.com

`h_in_address`: UDP listen address that receive data from hysteria/kcp/wireguard..., in the server that you run
hysteria/kcp/wireguard/... client you should set this address as endpoint (target address) in your
hysteria/kcp/wireguard/... client config, and in the other side that run hysteria/kcp/wireguard/... server, this address
port is not important and you can choose any port.

`h_out_address`: set it only on the side that you run hysteria/kcp/wireguard/... server, and this the address that
hysteria/kcp/wireguard/... server that listen to, in the other side that run hysteria/kcp/wireguard/... client leave it
empty (in client side h_out_address automatically is set to the last address that receive data from)

`max_domain_len`: maximum length of final domain length that resolver allow to pass, (count without trailing dot, for
example the length of a.b.com is 7), in theory, resolvers should support up to 253 domain length, but some resolvers
limited to lower value (99/101/151/...).
if you use multiple dns, this value must be set to a minimum value that all dns support.

`max_sub_len`: maximum length of each subdomain-part (parts between two dots), in theory, resolvers should support up to
63 for each part.

`retries`: nubmer of retries, for example if set to 2, each data is send 3 times.all tries is sent immediately, so if
you set it to 2, your bandwidth usage is multiplied by 3, because received data usually needs to split into parts, and
we may have packet lost for some parts, this option help to reduce packet lost, but increase bandwidth usage (
hysteria/kcp/wireguard/... retransmit data if they don't receive it's ACK, so you don't need to set this too high,
recommend value is 1)

`send_query_type_int`: integer query type of sending DNS-Query ("A": 1, "AAAA": 28, "TXT": 16,...)

`recv_query_type_int`: integer query type of DNS-Query that you expect to receive, this is other side
send_query_type_int

`chksum_pass`: the password that prevent to receive unauthorized/corrupted data, must be the same on both sides.

`packets_send_interval`: packets are sent at this interval (in seconds) for each dns_ip, also if data splits into parts,
each part is sent at this interval, so the actual time it takes to send a packet will be this value multiplied by the
number of its parts. this is necessary because most resolvers has rate limit.

`send_sock_numbers`: number of udp sockets that use for sending data, for bypassing resolvers rate limit, it is better
to send data with different source ports (so we use multiple sockets with different source port to send data), you may
need to run "ulimit -n 32768" to increase limit of number of file descriptors.

# Tips

1. don't forget to open udp port 53 on both sides.
2. make sure dns_ips work before setting them up, the other side always send NOERROR-EMPTY-RESPONSE in response of each
   request, so first run the tunnel on the other side, then for each dns_ip run "dig @%dns_ip %send_domain
   %send_query_type", if you receive NOERROR-EMPTY-RESPONSE, it indicates that the dns_ip is working.
   also, dns_Out2Iran.txt file contains some scanned dns to use for outside-to-Iran and there are many more options for
   Iran-to-outside dns.
   using multiple dns improve speed, but be careful that all DNS must be active, otherwise the tunnel will not function
   properly.
   also, max_domain_len must be set to a minimum value that all dns support.

# Donate

`USDT (BEP20)`: 0x76a768B53Ca77B43086946315f0BDF21156bF424
