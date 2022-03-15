import struct 

def get_ipv4(addr):
    return '.'.join(map(str,addr))

def ipv4_packet(data):
    version = data[0] >> 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version,ttl,proto,get_ipv4(src),get_ipv4(target)