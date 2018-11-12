#!/usr/bin/env python
# coding: utf-8

# In[ ]:


class EthernetFrame():
    def __init__(self, packet_bytes):
        self.dst = packet_bytes[0:6]
        self.src = packet_bytes[6:12]
        self.type = packet_bytes[12:14]
        self.data = packet_bytes[14:]


class IPv4_Packet():
    def __init__(self, data):
        self.version = data[0] >> 4
        
        # extract header length (number of 32-bit words in the header)
        ihl     = data[0] & int('00001111', 2)
        header_size = ihl * 4 # so multiply by 4 to get the number of bytes
        
        # get the total size of the packet (header + data)
        total_size = int(binascii.hexlify(data[2:4]), 16)
        
        # set the internal values (this also drops the padding from the internet frame)
        self.header = data[0:header_size]
        self.data = data[header_size:total_size]
        self.protocol = data[9]
        self.src_ip = data[12:16]
        self.dst_ip = data[16:20]
        

def get_eth_frame(packet_block):
    # Check that the block's associated interface is the LINKTYPE_ETHERNET (link_type = 1)
    # Src: https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html#appendixLinkTypes
    if not packet_block.interface.link_type == 1:
        return None
    
    packet_data = packet_block.packet_data
    ethernet_frame = EthernetFrame(packet_data)
    return ethernet_frame

        
def get_ipv4_packet(ethernet_frame):
    # Check that the ethernet frame has tpye 0x0800 and is IPv4
    if not ethernet_frame.type == b'\x08\x00':
        return None
    
    ipv4_packet = IPv4_Packet(ethernet_frame.data)
    return ipv4_packet

