#!/usr/bin/env python
# coding: utf-8

# In[ ]:


from pcapng import FileScanner
from pcapng import blocks

import classes


def get_pcap_packet_blocks(filename):
    """
    Reads a pcap file and creates a list of EnhancedPacket blocks from the file.
    """
    packet_blocks = []
    with open(filename, 'rb') as fp:
        scanner = FileScanner(fp)
        for block in scanner:
            if isinstance(block, blocks.EnhancedPacket):
                packet_blocks.append(block)

    return packet_blocks


def add_to_database(packet_len, timestamp, src_port, dst_port, proto, src_ip, dst_ip, data):
    pass


def parse_file_and_add(filename):
    packet_blocks = []
    packet_blocks = get_pcap_packet_blocks(filename)
    for pb in packet_blocks:
    ethernet_frame = classes.get_eth_frame(pb)
    if ethernet_frame:
        ipv4_packet = classes.get_ipv4_packet(ethernet_frame)
        if ipv4_packet:
            db.add_to_database(pb.packet_len,
                               pb.timestamp,
                               ethernet_frame.src,
                               ethernet_frame.dst,
                               ipv4_packet.protocol,
                               ipv4_packet.src_ip,
                               ipv4_packet.dst_ip,
                               ipv4_packet.data)

