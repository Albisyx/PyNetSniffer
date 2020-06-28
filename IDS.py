from scapy.layers.inet import *

# Module that implement the intrusion detection capabilities.
# The two attacks that will be detected are:
# 1) port scanning attempts
# 2) SYN Flood attack


# The following method is called whenever a packet is sniffed on the selected
# interface and it initializes the process of detecting the attacks.
def inspect_packets(packet):
    # First we have to ignore packets that don't contain an IP header
    if IP not in packet:
        return

    # Both port scanning and SYN Flood use TCP, so let's discard all packets that
    # don't contain a TCP header.
    if TCP not in packet:
        return

    # At this point we have a packet which for sure has a TCP segment.
    # Now it's time to detect possible attacks.
    detect_port_scanning(packet[TCP])
    detect_syn_flood(packet[TCP])


def detect_port_scanning(tcp_segment):
    pass


def detect_syn_flood(tcp_segment):
    pass
