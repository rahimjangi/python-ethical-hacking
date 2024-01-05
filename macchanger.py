import argparse
import re
import subprocess

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

        print(f"MAC address of {interface} changed to {new_mac}")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")    

def main():
    parser = argparse.ArgumentParser(description="Change MAC address of a network interface.")
    parser.add_argument("-i", "--interface", required=True, help="Interface to change MAC address")
    parser.add_argument("-m", "--mac", required=True, help="New MAC address of the interface")
    args = parser.parse_args()

    # Validate MAC address
    if not validate_mac_address(args.mac):
        parser.error("Invalid MAC address format")

    # Your logic to change MAC address
    print(f"Changing MAC address for interface {args.interface} to {args.mac}")
    mac=args.mac
    interface=args.interface
    change_mac_address(interface,mac)
    


if __name__ == "__main__":
    main()
