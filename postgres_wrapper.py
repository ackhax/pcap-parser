import pandas as pd
import sqlalchemy

from datetime import datetime

import classes
from postgres_config import *

def convert_to_dataframe(packet_blocks):
    
    index = [] # This will be the timestamps of each packet we add    
    rows = [] # Use this list to build the dataframe quickly
    
    for pb in packet_blocks:
        eth_frame = classes.get_eth_frame(pb)
        if eth_frame:
            ipv4_packet = classes.get_ipv4_packet(eth_frame)
            if ipv4_packet:
                # Add timestamp to index list
                index.append(datetime.fromtimestamp(pb.timestamp))
                
                # Create a dictionary with each key being the name of the column, appending it to the rows list
                d = {}
                d['packet_type'] = 'ipv4'
                d['packet_len']  = pb.packet_len
                d['src_port']    = eth_frame.src
                d['dst_port']    = eth_frame.dst
                d['proto']       = ipv4_packet.protocol
                d['src_ip']      = ipv4_packet.src_ip
                d['dst_ip']      = ipv4_packet.dst_ip
                d['data']        = ipv4_packet.data
                rows.append(d)

    # Create a dataframe with the index list and data rows
    df = pd.DataFrame(index=index, data=rows)
    return df


def add_to_database(df, table_name):
    # The to_sql function converts to data frame into an sql command
    # and insert it into the sqlalchemy engine we created already
    
    engine = sqlalchemy.create_engine('postgres://{}:{}@{}/postgres'.format(DB_USER, DB_PASS, DB_HOST))
    connection = engine.connect()
    
    # One nuance here with using sqlalchemy is we need to specify types for each column. Luckily,
    # we can easily add a dytpe dict to define these.  We can use the LargeBinary type for the data
    # that we have left as byte strings.
    dtype = {
                'packet_type': sqlalchemy.types.String,
                'packet_len': sqlalchemy.types.Integer,
                'src_port': sqlalchemy.types.LargeBinary,
                'dst_port': sqlalchemy.types.LargeBinary,
                'proto': sqlalchemy.types.Integer,
                'src_ip': sqlalchemy.types.LargeBinary,
                'dst_ip': sqlalchemy.types.LargeBinary,
                'data': sqlalchemy.types.LargeBinary
    }
    df.to_sql(table_name, connection, dtype=dtype)
    connection.close()

