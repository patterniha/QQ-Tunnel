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
