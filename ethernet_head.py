'''
For Ethernet II Frame
Ethernet Header first 14 bytes
MAC destination address = 6 bytes
MAC source address = 6 bytes
Ether type = 2 bytes
Rest is CRC check sum

resource : https://www.geeksforgeeks.org/ethernet-frame-format/
'''

from struct import *
class EthHead:
    def __init__(self,data):
        self.data = data
    
    # def eth_addr(self,a):
    #     address = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord[a[0]],ord[a[1]],ord[a[2]],ord[a[3]],ord[a[4]],ord[a[5]])
    #     return address
    
    def mac_dest(self):
        return self.data[0:6]
    
    def mac_src(self):
        return self.data[6:12]
    
    def ether_type(self):
        eth_head = self.data[:14]
        eth = unpack('!6s6sH', eth_head)
        return str(eth[2])

        


