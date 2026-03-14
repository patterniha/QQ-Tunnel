import sys
import subprocess
import ctypes
from ctypes import wintypes

SIO_UDP_CONNRESET = 0x9800000C


def disable_udp_connreset(sock):
    flag = wintypes.BOOL(False)  # FALSE disables the behavior
    bytes_returned = wintypes.DWORD()

    ws2_32 = ctypes.WinDLL("ws2_32", use_last_error=True)

    ret = ws2_32.WSAIoctl(
        sock.fileno(),
        SIO_UDP_CONNRESET,
        ctypes.byref(flag),
        ctypes.sizeof(flag),
        None,
        0,
        ctypes.byref(bytes_returned),
        None,
        None
    )

    if ret != 0:
        raise ctypes.WinError(ctypes.get_last_error())


def block_icmp_port_unreachable():
    """
    Linux only: block incoming ICMP Port Unreachable (Type 3, Code 3)
    at the earliest netfilter stage (raw PREROUTING) to prevent
    EPERM errors and error queue memory leaks on UDP sockets.

    On Windows, use disable_udp_connreset() per socket instead.
    """
    if sys.platform == "win32":
        return

    try:
        # Check if the rule already exists
        check = subprocess.run(
            ["iptables", "-t", "raw", "-C", "PREROUTING",
             "-p", "icmp", "--icmp-type", "3/3", "-j", "DROP"],
            capture_output=True
        )
        if check.returncode == 0:
            return

        result = subprocess.run(
            ["iptables", "-t", "raw", "-A", "PREROUTING",
             "-p", "icmp", "--icmp-type", "3/3", "-j", "DROP"],
            capture_output=True
        )
        if result.returncode != 0:
            print("Failed to add iptables rule:", result.stderr.decode().strip())
        else:
            print("iptables rule added: block ICMP Port Unreachable (raw PREROUTING)")

    except FileNotFoundError:
        print("iptables not found, cannot block ICMP Port Unreachable. "
              "Install iptables or manually add an nftables rule.")
