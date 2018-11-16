#!/usr/bin/env python
from pcapng import FileScanner
from pcapng import blocks

import postgres_wrapper as db


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


def parse_file_and_add(filename, table_name):
    packet_blocks = []
    packet_blocks = get_pcap_packet_blocks(filename)
    df = db.convert_to_dataframe(packet_blocks)
    db.add_to_database(df, table_name)