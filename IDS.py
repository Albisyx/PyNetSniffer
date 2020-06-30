import time as t
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
        self.local_ip = gethostbyname(gethostname())  # local IP address
        self.time_first_syn = 0  # timestamp of the first TCP SYN packet encountered
        self.tcp_syn_count = 0
        self.PORT_SCAN_THRESHOLD = 500
        self.TCP_SYN_THRESHOLD = 500
        self.SYN_FLOOD_DETECT_TIME = 3  # number of seconds within a SYN Flood attack must be detected

    # The following method is called whenever a packet is sniffed on the selected
    # interface and it initializes the process of detecting the attacks.
    # It also performs the packets logging to a file.
    def inspect_packets(self, packet):
        # First we have to ignore packets that don't contain an IP header
        if IP not in packet:
            return

        # Let's discard all packets that are not TCP, UDP or ICMP in order to log them
        if TCP not in packet and \
           UDP not in packet and \
           ICMP not in packet:
            return

        # At this point we have a packet which for sure has an IP header
        # and it contains TCP, UDP or ICMP segment.

        # Log packets to a file


        # Now it's time to detect possible attacks.
        # Since the detectable attacks use only TCP, let's filter packets that have not
        # a TCP segment and the ones that are from our machine
        if TCP in packet and packet[IP].src != self.local_ip:
            self.detect_port_scanning(packet)
            #self.detect_syn_flood(packet)

    def detect_port_scanning(self, pkt):
        flags = pkt[TCP].flags
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

    # This method tries to detect a SYN Flood attack by using an interval of time.
    # Basically it starts a timer when the first TCP SYN packet is encountered.
    # If it detect a large number of SYN packets before the timer is elapsed, a SYN flood attack is may happening.
    def detect_syn_flood(self, pkt):
        if pkt[TCP].flags == 'S':
            if self.time_first_syn <= 0:
                self.time_first_syn = t.time()
            elif t.time() < (self.time_first_syn + self.SYN_FLOOD_DETECT_TIME):
                # If we are here and we detect a huge amount of SYN packets,
                # a SYN Flood attack is may happening.
                self.tcp_syn_count += 1
                if self.tcp_syn_count >= self.TCP_SYN_THRESHOLD:
                    print("{} is performing a SYN Flood attack with {} packets".format(pkt[IP].src, self.tcp_syn_count))
            else:
                # If we are here it means that the timer is elapsed, so we need to reset some attributes
                self.tcp_syn_count = 0
                self.time_first_syn = 0

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
