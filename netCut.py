#!/usr/bin/env python
# [-] echo 1 > /proc/sys/net/ipv4/ip_forward
# [-] iptables -I RORWARD -j NFQUEUE --queue-num 0
# from netfilterqueue import NetfilterQueue
import netfilterqueue
import traceback

def process_packet(packet):
    """
    Process each packet captured by NetfilterQueue.
    :param packet: The packet object.
    """
    try:
        print(packet)
        packet.accept()  # Uncomment to forward the packet
    except Exception as e:
        print(f"Error processing packet: {e}")

def main():
    """
    Main function to setup and run the NetfilterQueue.
    """
    try:
        # Create an instance of NetfilterQueue
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
        print("Queue unbound and program terminated.")

if __name__ == "__main__":
    main()
