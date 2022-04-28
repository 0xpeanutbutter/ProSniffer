import socket
import sys
from colorama import Fore, Style
import ethernet
import ipv4
import ipv6
import protocol_parser
import print_style

# socket_type = 'all'
ipv6_flag = True
ipv4_flag = True
udp_flag = True
tcp_flag = True
cmd = ""

print_style.logo()


n = len(sys.argv)
if n == 2:
    cmd = sys.argv[1].upper()
    if cmd == "-h" or cmd == "--help":
        print(
            "Flag usage : \n 1.tcp : for tcp packets \n 2.udp : for udp packets \n 3.-h/--help \n 4.default : all\n"
        )
    elif cmd == "TCP":
        ipv4_flag = True
        tcp_flag = True
        udp_flag = False
        ipv6_flag = False
        print("TCP filter chosed\n")
    elif cmd == "UDP":
        ipv4_flag = True
        udp_flag = True
        tcp_flag = False
        ipv6_flag = False
        print("UDP packet")
    elif cmd == "IPV6":
        ipv6_flag = True
        ipv4_flag = False
        print("IPV6 packet")
    elif cmd == "IPV4":
        ipv4_flag = True
        udp_flag = True
        tcp_flag = True
        ipv6_flag = False
        print("IPV4 packet")
else:
    print("Default filter: \n")

ips = [
    (s.connect(("8.8.8.8", 53)), s.getsockname()[0], s.close())
    for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]
]
ips = list(ips[0])


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    while True:
        raw_data, addr = conn.recvfrom(65536)
        # maximum buffer size is 65536
        dest_mac, src_mac, ethertype, data = ethernet.ethernet_frame(raw_data)

        # if IPv4
        if ethertype == 8 and ipv4_flag:
            version, ttl, header_len, src_ip, dest_ip, proto, data = ipv4.ipv4_packet(
                data
            )
            if str(src_ip) in ips:
                print(Fore.RED + "\t\t Outgoing Packet" + Style.RESET_ALL)
            elif str(dest_ip) in ips:
                print(Fore.RED + "\t\t Incoming Packet" + Style.RESET_ALL)

            if proto == 1 and (cmd == "IPV4" or n ==1):
                print("\n Ethernet Frame II : ")
                print(
                    "\t Destination MAC adress {}, source MAC Address {}, Protocol : {}".format(
                        dest_mac, src_mac, ethertype
                    )
                )
                print(Fore.CYAN + "\t IPv4 Packet : " + Style.RESET_ALL)
                print(
                    "\t\t Version : {}, TTL : {}, Header Length ".format(
                        version, ttl, header_len
                    )
                )
                print(
                    "\t\t\t Protocol : {}, Source : {}, Destination : {}".format(
                        proto, src_ip, dest_ip
                    )
                )
                protocol_parser.icmp_parser(data)
                print("\n")
                print_style.H()
                print("\n")
            elif proto == 6 and tcp_flag:
                print("\n Ethernet Frame II : ")
                print(
                    "\t Destination MAC adress {}, source MAC Address {}, Protocol : {}".format(
                        dest_mac, src_mac, ethertype
                    )
                )
                print(Fore.CYAN + "\t IPv4 Packet : " + Style.RESET_ALL)
                print(
                    "\t\t Version : {}, TTL : {}, Header Length:{} ".format(
                        version, ttl, header_len
                    )
                )
                print(
                    "\t\t\t Protocol : {}, Source : {}, Destination : {}".format(
                        proto, src_ip, dest_ip
                    )
                )
                protocol_parser.tcp_parser(raw_data)
                print("\n")
                print_style.H()
                print("\n")
            elif proto == 17 and udp_flag:
                print("\n Ethernet Frame II : ")
                print(
                    "\t Destination MAC adress {}, source MAC Address {}, Protocol : {}".format(
                        dest_mac, src_mac, ethertype
                    )
                )
                print(Fore.CYAN + "\t IPv4 Packet : " + Style.RESET_ALL)
                print(
                    "\t\t Version : {}, TTL : {}, Header Length ".format(
                        version, ttl, header_len
                    )
                )
                print(
                    "\t\t\t Protocol : {}, Source : {}, Destination : {}".format(
                        proto, src_ip, dest_ip
                    )
                )
                protocol_parser.udp_parser(data)
                print("\n")
                print_style.H()
                print("\n")

        # if IPv6
        elif ethertype == 56710 and ipv6_flag:
            print("\n Ethernet Frame II : ")
            print(
                "\t Destination MAC adress {}, source MAC Address {}, Protocol : {}".format(
                    dest_mac, src_mac, ethertype
                )
            )
            ipv6.ipv6_packet(data)
            print("\n")
            print_style.H()
            print("\n")


main()
