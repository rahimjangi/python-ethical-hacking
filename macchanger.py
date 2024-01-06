#!/usr/bin/env python

import argparse
import re
import subprocess

def get_options(interfaces):
    parser = argparse.ArgumentParser(description="Change MAC address of a network interface.")
    parser.add_argument("-i", "--interface", required=True, help="Interface to change MAC address")
    parser.add_argument("-m", "--mac", required=True, help="New MAC address of the interface")
    args=parser.parse_args()
    #  Validate Interface
    if args.interface not in interfaces:
        print(f"The interface '{args.interface}' does not exist!")
        exit()

    # Validate MAC address
    if not validate_mac_address(args.mac):
        print("Invalid MAC address format")
        exit()
    return args

def validate_mac_address(mac):
    # Regular expression to check if the MAC address is valid
    pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
    if re.match(pattern, mac):
        return True
    else:
        return False
def change_mac_address(interface, new_mac):
    try:
        # Bring down the interface
        subprocess.run(["sudo", "ip", "link", "set", "dev", interface, "down"], check=True)

        # Change the MAC address
        subprocess.run(["sudo", "ip", "link", "set", "dev", interface, "address", new_mac], check=True)

        # Bring up the interface
        subprocess.run(["sudo", "ip", "link", "set", "dev", interface, "up"], check=True)

        
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")  
        
def get_network_interfaces():
    try:
        # Execute the 'ip link' command to get network interfaces
        result = subprocess.run(["ip", "link"], capture_output=True, text=True, check=True)
        
        # Extract interface names using a regular expression
        # The pattern looks for words after '... <...>: '
        interfaces = re.findall(r'\d+: ([^:]+):', result.stdout)
        return interfaces
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")
        return []  
def chech_if_mac_changed(interface):
    pattern=r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"
    result = subprocess.run(["ifconfig", interface], capture_output=True, text=True, check=True)
    macs=re.search(pattern=pattern, string=result.stdout)
    if macs:
        return macs.group(0)

def main():
    interfaces=get_network_interfaces()
    args = get_options(interfaces)
    print(f"Changing MAC address for interface {args.interface} to {args.mac}")
    change_mac_address(args.interface,args.mac)
    if chech_if_mac_changed(args.interface)==args.mac:
        print(f"MAC address of {args.interface} changed to {args.mac}")
    


if __name__ == "__main__":
    main()
