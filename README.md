# network-sniffer
network sniffer 
from scapy.all import sniff

# Callback function to process captured packets
def packet_callback(packet):
    print(packet.summary())

# Sniffing function to capture packets
def start_sniffing(interface):
    sniff(iface=interface, prn=packet_callback)

def new_func(start_sniffing):
    start_sniffing()

if __name__ == "__main__":
    # Replace 'eth0' with your network interface
    network_interface = "eth0"
    print(f"Starting network sniffer on interface {network_interface}")
    new_func(start_sniffing)
