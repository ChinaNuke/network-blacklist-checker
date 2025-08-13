#!/usr/bin/env python3

import argparse
from scapy.all import rdpcap, IP, TCP, DNS, DNSQR
from collections import defaultdict
import sys

def extract_reset_ips(pcap_file):
    """Extract source IP addresses from packets with TCP reset flag set."""
    reset_ips = set()
    
    try:
        packets = rdpcap(pcap_file)
        print(f"Loaded {len(packets)} packets from {pcap_file}")
        
        for packet in packets:
            if IP in packet and TCP in packet:
                tcp_layer = packet[TCP]
                if tcp_layer.flags & 0x04:  # RST flag is bit 2 (0x04)
                    src_ip = packet[IP].src
                    reset_ips.add(src_ip)
                    
    except Exception as e:
        print(f"Error reading PCAP file: {e}")
        sys.exit(1)
        
    return reset_ips

def extract_dns_mappings(pcap_file):
    """Extract DNS A record mappings from the PCAP file."""
    dns_mappings = {}
    
    try:
        packets = rdpcap(pcap_file)
        
        for packet in packets:
            if DNS in packet:
                dns_layer = packet[DNS]
                
                # Check if this is a DNS response with answers
                if dns_layer.qr == 1 and dns_layer.ancount > 0:
                    # Extract query name from question section
                    if dns_layer.qd:
                        query_name = dns_layer.qd.qname.decode('utf-8').rstrip('.')
                        
                        # Extract A records from answer section
                        for i in range(dns_layer.ancount):
                            if i < len(dns_layer.an):
                                answer = dns_layer.an[i]
                                if answer.type == 1:  # A record
                                    ip_addr = answer.rdata
                                    dns_mappings[ip_addr] = query_name
                                    
    except Exception as e:
        print(f"Error extracting DNS mappings: {e}")
        
    return dns_mappings

def main():
    parser = argparse.ArgumentParser(description='Analyze PCAP for TCP reset sources and their DNS mappings')
    parser.add_argument('pcap_file', help='Path to the PCAP file to analyze')
    args = parser.parse_args()
    
    print("Extracting source IPs from TCP reset packets...")
    reset_ips = extract_reset_ips(args.pcap_file)
    print(f"Found {len(reset_ips)} unique IPs that sent TCP reset packets")
    
    print("\nExtracting DNS A record mappings...")
    dns_mappings = extract_dns_mappings(args.pcap_file)
    print(f"Found {len(dns_mappings)} DNS A record mappings")
    
    print("\n" + "="*60)
    print("DOMAIN NAME -> IP ADDRESS MAPPINGS FOR RESET SOURCES")
    print("="*60)
    
    found_mappings = 0
    for reset_ip in sorted(reset_ips):
        if reset_ip in dns_mappings:
            domain = dns_mappings[reset_ip]
            print(f"{domain:40} -> {reset_ip}")
            found_mappings += 1
        else:
            print(f"{'<no DNS mapping found>':40} -> {reset_ip}")
    
    print("\n" + "="*60)
    print(f"Summary: {found_mappings}/{len(reset_ips)} reset IPs have corresponding DNS mappings")

if __name__ == "__main__":
    main()