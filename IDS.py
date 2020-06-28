from scapy.layers.inet import *
from socket import gethostname, gethostbyname

# Module that implement the intrusion detection capabilities.
# The two attacks that will be detected are:
# 1) port scanning attempts
# 2) SYN Flood attack

tcp_syn = dict()


# The following method is called whenever a packet is sniffed on the selected
# interface and it initializes the process of detecting the attacks.
def inspect_packets(packet):
    # First we have to ignore packets that don't contain an IP header
    if IP not in packet:
        return

    # Now that we are sure to deal with an IP packet, let's check if it is directed to
    # our machine. We only want to inspect packets addressed to us.
    local_ip = gethostbyname(gethostname())  # local IP address
    if packet[IP].dst != local_ip:
        return

    # At this point we have a packet which for sure has an IP
    # header and it is directed to our machine.
    # Now it's time to detect possible attacks.
    detect_port_scanning(packet)
    detect_syn_flood(packet)


def detect_port_scanning(pkt):
    # TCP SYN scan detection
    source_ip = pkt[IP].src
    flags = str(pkt[TCP].flags)
    if flags == 'S':  # SYN bit is set
        if source_ip not in tcp_syn:
            tcp_syn[source_ip] = {"SYN" : 0, "SYN-ACK" : 0}
        tcp_syn[source_ip]["SYN"] += 1
    elif flags == 'SA':  # SYN and ACK bits are set
        if source_ip not in tcp_syn:
            tcp_syn[source_ip] = {"SYN" : 0, "SYN-ACK" : 0}
        tcp_syn[source_ip]["SYN-ACK"] += 1


def detect_syn_flood(pkt):
    pass
