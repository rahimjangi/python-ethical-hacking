#!/usr/bin/env python
# [-] echo 1 > /proc/sys/net/ipv4/ip_forward
# [-] iptables -I INPUT -j NFQUEUE --queue-num 0
# [-] iptables -I OUTPUT -j NFQUEUE --queue-num 0
# from netfilterqueue import NetfilterQueue
import netfilterqueue
import subprocess
import scapy.all as scapy

def run_command(command):
    """
    Run a system command using subprocess.
    :param command: Command to be executed as a list.
    """
    try:
        subprocess.run(command, check=True)
        print(f"Executed command: {' '.join(command)}")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while executing {' '.join(command)}: {e}")

def setup_iptables():
    """
    Set up iptables rules and enable IP forwarding.
    """
    commands = [
        ["sysctl", "-w", "net.ipv4.ip_forward=1"],  # Enable IP forwarding
        ["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"],  # Set iptables rules for INPUT
        ["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"]  # Set iptables rules for OUTPUT
    ]

    for command in commands:
        run_command(command)
def flush_iptables():
    """
    Flush all iptables rules.
    """
    commands = [
        ["iptables", "--flush"],  # Flush all rules
        ["iptables", "--delete-chain"]  # Delete all user-defined chains
    ]

    for command in commands:
        try:
            subprocess.run(command, check=True)
            print(f"Flushed iptables with command: {' '.join(command)}")
        except subprocess.CalledProcessError as e:
            print(f"An error occurred while flushing iptables: {e}")


queue = netfilterqueue.NetfilterQueue()

def process_packet(packet):
    """
    Process each packet captured by NetfilterQueue.
    :param packet: The packet object.
    """
    try:
        scapy_packet=scapy.IP(packet.get_payload())
        print(scapy_packet.show())
        packet.accept()  # Uncomment to forward the packet
    except Exception as e:
        print(f"Error processing packet: {e}")

def main():
    """
    Main function to setup and run the NetfilterQueue.
    """
    try:
        # Create an instance of NetfilterQueue
        setup_iptables()
        nf_queue = netfilterqueue.NetfilterQueue()

        # Bind the instance to a specific queue number and assign the callback
        nf_queue.bind(0, process_packet)

        print("Starting packet processing...")
        nf_queue.run()
    except KeyboardInterrupt:
        print("Stopping packet processing...")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        nf_queue.unbind()  # Unbind from the queue
        flush_iptables()
        print("Queue unbound and program terminated.")

if __name__ == "__main__":
    main()