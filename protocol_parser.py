import struct


def tcp_parser(raw_data):
    (
        src_port,
        dest_port,
        seq,
        ack,
        urg_flag,
        ack_flag,
        psh_flag,
        rst_flag,
        syn_flag,
        fin_flag,
    ) = struct.unpack("! H H L L H H H H H H", raw_data[:24])
    print("\t TCP Segment : \n")
    print("\t\t Source Port : {}, Destination Port : {}".format(src_port, dest_port))
    print("\t\t Sequence: {}, Acknowledgemnt : {}".format(seq, ack))


def udp_parser(data):
    src_port, dest_port, size = struct.unpack("! H H 2x H", data[:8])
    print("\t UDP Segment : \n")
    print("\t\t Source Port : {}, Destination Port : {}".format(src_port, dest_port))


def icmp_parser(data):
    icmp_type, code, checksum = struct.unpack("! B B H", data[:4])
    print("\t ICMP Packet : \n")
    print("\t\t Type : {}, Code : {}, Checksum : {}".format(icmp_type, code, checksum))
