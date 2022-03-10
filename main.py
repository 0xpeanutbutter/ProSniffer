'''
socket.ntohs(0x0003) captures all send and receive packets from the network
'''

import socket
from ethernet_head import EthHead

def prettify(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b

def main():
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
    while True:
        data = s.recvfrom(65565)
        #recvfrom returns two values. 1 packet,2 addr
        packet = data[0]
        ethernet_frame = EthHead(packet)
        destination = prettify(ethernet_frame.mac_dest())
        source = prettify(ethernet_frame.mac_src())
        ethertype = ethernet_frame.ether_type()
        print(destination,source,ethertype)

main()
