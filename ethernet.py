import struct
import socket


def get_mac(byte_addr):
    mac_str = map("{:02x}".format, byte_addr)
    return ":".join(mac_str).upper()


# Unpacking ethernet Frame II
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", data[:14])
    return get_mac(dest_mac), get_mac(src_mac), socket.htons(proto), data[14:]
