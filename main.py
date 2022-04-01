import socket
import sys
import ethernet
import ipv4

socket_type = socket.SOCK_RAW
n = len(sys.argv)
if(n==2):
    cmd = sys.argv[1]
    if(cmd == '-h' or cmd == '--help'):
        print('Flag usage : \n 1.tcp : for tcp packets \n 2.udp : for udp packets \n 3.-h/--help \n 4.default : all\n')
    elif(cmd.upper() == 'TCP'):
        print('TCP filter chosed\n')
        socket_type = socket.SOCK_STREAM
    elif(cmd.upper() == 'UDP'):
        socket_type = socket.SOCK_DGRAM
else:
    print('Default filter: \n')

def main():
    conn = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
    while True:
        raw_data, addr = conn.recvfrom(65536) 
        #maximum buffer size is 65536
        '''
        Getting Ethernet frame and printing it
        Using the ethertype to choose type of IP
        '''
        dest_mac, src_mac, ethertype, data = ethernet.ethernet_frame(raw_data)
        # print(dest_mac,ethertype)
        print("\n Ethernet Frame II : ")
        print("\t Destination MAC adress {}, source MAC Address {}, Protocol : {}".format(dest_mac,src_mac,ethertype))
        '''
        IPv4 : 0x0800 - htohs : 8
        IPv6 : 0x86DD - htohs : 56710
        ARP : 0x0806
        '''
        # if IPv4
        if(ethertype == 8):
            (version,ttl,proto,src_addr,dest_addr) = ipv4.ipv4_packet(data) 
            print("\t IPv4 Packet")
            print("\t\t Version : {}, TTL : {}".format(version,ttl))
            print("\t\t\t Protocol : {}, Source : {}, Destination : {}".format(proto,src_addr,dest_addr))
            '''
            TCP : 6
            UDP : 17
            ICMP : 1
            '''
        # if IPv4
        elif(ethertype == 56710):
            print("/t IPV6 Packet")
        print('\n\n')

