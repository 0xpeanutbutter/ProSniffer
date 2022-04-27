import struct
import socket
from colorama import Fore, Style


def ipv6_packet(data):
    first_32_bytes, payload_len, next_header, hop_limit = struct.unpack(
        "! IHBB", data[:8]
    )
    version = first_32_bytes >> 28
    traffic_class = (first_32_bytes >> 20) & 255
    flow_label = first_32_bytes & 1048575

    src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dest_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])
    print(Fore.CYAN + "\t IPv6 Packet : " + Style.RESET_ALL)
    print(
        "\t\t Version : {}, Traffic Class : {} Flow Label : {}".format(
            version, traffic_class, flow_label
        )
    )
    print("\t\t\t Source : {}, Destination : {}".format(src_ip, dest_ip))
