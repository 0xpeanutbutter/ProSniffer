import struct
from colorama import Fore, Style


def get_ipv4(addr):
    return ".".join(map(str, addr))


def ipv4_packet(data):
    version_header_length = data[0]
    header_len = (version_header_length & 15) * 4
    version = data[0] >> 4
    ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    return (
        version,
        ttl,
        header_len,
        get_ipv4(src),
        get_ipv4(target),
        proto,
        data[header_len:],
    )
