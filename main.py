"""Author: <Caeden Jackson>
   Date: 04/26/25 """

import pyshark
import pandas as pd


def main():
# Ask user to input the path to the .pcap file
    file_path = input("Enter the full path to the .pcap or .pcapng file: ")

# Load the capture file
    try:
        capture = pyshark.FileCapture(file_path)
    except Exception as e:
        print(f"Error opening file: {e}")
        exit()

    tcp_packets = []
    for packet in capture:
        if packet.transport == "tcp":
            tcp_packets.append({
            "src_ip":packet.ip.src,
            "src_port":packet.ip.src,
            "dst_ip":packet.ip.dst,
            "dst_port":packet.ip.dst,
            "time":packet.frame_info.time,
            "length":packet.frame_info.len,
            })

    df = pd.DataFrame(tcp_packets)

    """Example Information"""
    ack_packets = df[df["tcp.flags"].str.contains("ACK")]
    print(ack_packets.head())

    syn_packets = df[df["tcp.flags"].str.contains("SYN")]
    print(syn_packets.head())

main()