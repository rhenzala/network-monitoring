import threading
import pandas as pd
from datetime import datetime
from scapy.all import IP, TCP, UDP
import logging


logger = logging.getLogger(__name__)

protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
packet_data = []
start_time = datetime.now()
packet_count = 0
lock = threading.Lock()

def get_protocol_name(protocol_num: int) -> str:
    """Convert protocol number to name"""
    return protocol_map.get(protocol_num, f'OTHER({protocol_num})')

def process_packet(packet) -> None:
    """Process a single packet and extract relevant information"""
    global packet_count
    try:
        if IP in packet:
            with lock:
                packet_info = {
                    'timestamp': datetime.now(),
                    'source': packet[IP].src,
                    'destination': packet[IP].dst,
                    'protocol': get_protocol_name(packet[IP].proto),
                    'size': len(packet),
                    'time_relative': (datetime.now() - start_time).total_seconds()
                }

                # Add TCP-specific information
                if TCP in packet:
                    packet_info.update({
                        'src_port': packet[TCP].sport,
                        'dst_port': packet[TCP].dport,
                        'tcp_flags': packet[TCP].flags
                    })

                # Add UDP-specific information
                elif UDP in packet:
                    packet_info.update({
                        'src_port': packet[UDP].sport,
                        'dst_port': packet[UDP].dport
                    })

                packet_data.append(packet_info)
                packet_count += 1

                # Keep only last 10000 packets to prevent memory issues
                if len(packet_data) > 10000:
                    packet_data.pop(0)
    except Exception as e:
        logger.error(f"Error processing packet: {str(e)}")

def get_dataframe() -> pd.DataFrame:
    """Convert packet data to pandas DataFrame"""
    with lock:
        return pd.DataFrame(packet_data)
    