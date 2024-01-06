#!/usr/bin/dev python
"""Please note that network scanning should only be conducted on networks where you have authorization to do so. Scanning networks without permission can be illegal and unethical. It's important to respect privacy and legal boundaries. You need to install 'scapy'
$: pip install scapy
"""

from scapy.all import ARP, Ether, srp
import nmap
import argparse


def get_options():
    parser = argparse.ArgumentParser(description="IP Address for the destination '192.168.1.1/24' - for example")
    parser.add_argument("-ip", "--ipaddress", required=True, help="IP address to scan")
    args=parser.parse_args()

    if args.ipaddress:    
        return args.ipaddress
    else:
        return "192.168.0.1/24"


def scan_network(ip):
    target_ip = ip
    # create ARP packet
    arp = ARP(pdst=target_ip)
    # create the Ether broadcast packet
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    # stack them
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    clients = []

    for sent, received in result:
        # for each response, append ip and mac address to `clients` list
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    # print clients
    print("Available devices in the network:")
    print("IP" + " " * 18 + "MAC")
    ip_list=[]
    for client in clients:
        print("{:16}    {}".format(client['ip'], client['mac']))
        ip_list.append(client['ip'])
    print("-"*37)
    return ip_list

def advanced_scan(ip_range):
    # Create a scanner object
    nm = nmap.PortScanner()

    # Scan the given IP range (substitute with your range)
    nm.scan(hosts=ip_range, arguments='-O')

    # Iterate over all hosts
    for host in nm.all_hosts():
        print(f'Host : {host} ({nm[host].hostname()})')
        print(f'State : {nm[host].state()}')

        for proto in nm[host].all_protocols():
            print(f'---------------------\nProtocol : {proto}')

            lport = nm[host][proto].keys()
            for port in lport:
                print(f'port : {port}\tstate : {nm[host][proto][port]["state"]}')

        # OS detection
        try:
            for osmatch in nm[host]['osmatch']:
                print(f'OS Match: {osmatch["name"]}')
        except KeyError:
            print('No OS Match found')

 
def main():
    ip=get_options()
    ip_list=scan_network(ip)
    for ip in ip_list:
         advanced_scan(ip)
    


if __name__ == "__main__":
    main()
