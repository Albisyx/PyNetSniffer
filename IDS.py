from scapy.layers.inet import *
from socket import gethostname, gethostbyname

# Class that implements the intrusion detection capabilities.
# The two attacks that will be detected are:
# 1) port scanning attempts
#    The following port scans attempts will be detected:
#    - TCP FIN port scanning
#    - TCP X-Mas port scanning
# 2) SYN Flood attack


class Detector:
    def __init__(self):
        self.tcp_fin = dict()
        self.tcp_xmas = dict()
        self.tcp_syn = dict()
        self.local_ip = gethostbyname(gethostname())  # local IP address
        self.PORT_SCAN_THRESHOLD = 500

    # The following method is called whenever a packet is sniffed on the selected
    # interface and it initializes the process of detecting the attacks.
    # It also performs the packets logging to a file.
    def inspect_packets(self, packet):
        # First we have to ignore packets that don't contain an IP header
        if IP not in packet:
            return

        # Now that we are sure to deal with an IP packet, let's check if it is directed to
        # our machine. We only want to inspect packets addressed to us.
        if packet[IP].src == self.local_ip:
            return

        # Let's discard all packets that are not TCP, UDP or ICMP
        if TCP not in packet and \
           UDP not in packet and \
           ICMP not in packet:
            return

        # At this point we have a packet which for sure has an IP
        # header, it contains TCP, UDP or ICMP segment and it is directed to our machine.
        # Now it's time to detect possible attacks.
        self.detect_port_scanning(packet)
        # detect_syn_flood(packet)

    def detect_port_scanning(self, pkt):
        source_ip = pkt[IP].src

        # We are about to detect only port scanning attempts that are made with TCP
        if TCP in pkt:
            flags = str(pkt[TCP].flags)
            if flags == 'F':  # TCP FIN scan detection
                if source_ip not in self.tcp_fin:
                    self.tcp_fin[source_ip] = {"FIN": 0}
                self.tcp_fin[source_ip]["FIN"] += 1
                self.tcp_fin_scan(pkt)
            elif flags == 'FPU':  # TCP x-Mas scan detection
                if source_ip not in self.tcp_xmas:
                    self.tcp_xmas[source_ip] = {"FIN-PSH-URG": 0}
                self.tcp_xmas[source_ip]["FIN-PSH-URG"] += 1
                self.tcp_xmas_scan(pkt)

    def tcp_fin_scan(self, pkt):
        for ip in self.tcp_fin.keys():
            if self.tcp_fin[ip]["FIN"] > self.PORT_SCAN_THRESHOLD:
                print("{} is performing a FIN port scan".format(pkt[IP].src))
                self.tcp_fin[ip]["FIN"] = 0

    def tcp_xmas_scan(self, pkt):
        for ip in self.tcp_xmas.keys():
            if self.tcp_xmas[ip]["FIN-PSH-URG"] > self.PORT_SCAN_THRESHOLD:
                print("{} is performing a X-Mas port scan".format(pkt[IP].src))
                self.tcp_xmas[ip]["FIN-PSH-URG"] = 0

    def detect_syn_flood(self, pkt):
        pass
        # source_ip = pkt[IP].src
        # flags = str(pkt[TCP].flags)
        # if flags == 'S':  # SYN bit is set
        #     if source_ip not in tcp_syn:
        #         tcp_syn[source_ip] = {"SYN" : 0, "SYN-ACK" : 0}
        #     tcp_syn[source_ip]["SYN"] += 1
        # elif flags == 'SA':  # SYN and ACK bits are set
        #     if source_ip not in tcp_syn:
        #         tcp_syn[source_ip] = {"SYN" : 0, "SYN-ACK" : 0}
        #     tcp_syn[source_ip]["SYN-ACK"] += 1
