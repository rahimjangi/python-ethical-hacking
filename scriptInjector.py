import logging
import subprocess
import re
from scapy.all import IP, TCP, Raw
import netfilterqueue

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def execute_system_commands(commands):
    """
    Execute a list of system commands.
    """
    for command in commands:
        try:
            subprocess.run(command, check=True)
            logging.info(f"Executed command: {' '.join(command)}")
        except subprocess.CalledProcessError as error:
            logging.error(f"Error executing {' '.join(command)}: {error}")

def setup_network_configuration():
    """
    Configure network settings and iptables rules.
    """
    commands = [
        ["sysctl", "-w", "net.ipv4.ip_forward=1"],
        # ["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"],
        # ["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"],
        ["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"]
    ]
    execute_system_commands(commands)

def clear_iptables():
    """
    Flush iptables rules and delete chains.
    """
    commands = [["iptables", "--flush"], ["iptables", "--delete-chain"]]
    execute_system_commands(commands)

def set_load(packet, load):
    """
    Set the load of the packet and recalculate necessary fields.
    """
    packet[Raw].load = load
    del packet[IP].len
    del packet[TCP].chksum
    return packet

def process_network_packet(packet):
    """
    Process a network packet.
    """
    try:
        scapy_packet = IP(packet.get_payload())
        if scapy_packet.haslayer(Raw) and scapy_packet.haslayer(TCP):
            if scapy_packet[TCP].dport == 80:
                logging.info("HTTP Request intercepted")
                load = str(scapy_packet[Raw].load)

                # Modify the Accept-Encoding header to request uncompressed data
                modified_load = re.sub(r"(Accept-Encoding:\s*).*?\\r\\n", "", load)
                if load != modified_load:
                    logging.info("Requesting uncompressed data in HTTP request")
                    modified_packet = set_load(scapy_packet, modified_load)
                    packet.set_payload(bytes(modified_packet))
                else:
                    logging.info("No modification necessary for this packet")
            elif scapy_packet[TCP].sport == 80:
                logging.info("HTTP Response intercepted")
                response_load = str(scapy_packet[Raw].load)
                logging.info(f"Response Payload: {response_load}")

        packet.accept()
    except Exception as ex:
        logging.error(f"Error processing packet: {ex}")
        packet.drop()



def main():
    queue = netfilterqueue.NetfilterQueue()
    try:
        setup_network_configuration()
        queue.bind(0, process_network_packet)
        logging.info("Starting packet processing...")
        queue.run()
    except KeyboardInterrupt:
        logging.info("Stopping packet processing...")
    except Exception as error:
        logging.error(f"An unexpected error occurred: {error}")
    finally:
        queue.unbind()
        clear_iptables()
        logging.info("Queue unbound and iptables cleared.")

if __name__ == "__main__":
    main()
