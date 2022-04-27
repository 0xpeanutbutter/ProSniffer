import struct
from colorama import Fore, Style


def get_ipv4(addr):
    return ".".join(map(str, addr))


def ipv4_packet(data):
    version = data[0] >> 4
    ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    print(Fore.CYAN + "\t IPv4 Packet : " + Style.RESET_ALL)
    print("\t\t Version : {}, TTL : {}".format(version, ttl))
    print(
        "\t\t\t Protocol : {}, Source : {}, Destination : {}".format(
            proto, get_ipv4(src), get_ipv4(target)
        )
    )