import struct
import time as t
from scapy.layers.inet import *
from scapy.layers.http import *
from socket import gethostname, gethostbyname

# Class that implements the intrusion detection capabilities.
# The two attacks that will be detected are:
# 1) port scanning attempts
#    The following port scans attempts will be detected:
#    - TCP FIN port scanning
#    - TCP X-Mas port scanning
# 2) SYN Flood attack


class Detector:
    def __init__(self, logger):
        self.packets_logger = logger
        # self.ids_logger = self.get_ids_logger()
        self.tcp_fin = dict()
        self.tcp_xmas = dict()
        self.local_ip = gethostbyname(gethostname())  # local IP address
        self.time_first_syn = 0  # timestamp of the first TCP SYN packet encountered
        self.tcp_syn_count = 0
        self.packets_count = 0  # A simple counter of all the sniffed packets
        self.PORT_SCAN_THRESHOLD = 500
        self.TCP_SYN_THRESHOLD = 500
        self.SYN_FLOOD_DETECT_TIME = 3  # number of seconds within a SYN Flood attack must be detected

    def get_ids_logger(self):
        pass

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

        self.packets_count += 1

        # It's time to log packets on a file
        self.packets_logger.info(self.stringify_packet(packet))

        # Now it's time to detect possible attacks.
        # Since the detectable attacks use only TCP, let's filter packets that have not
        # a TCP segment and the ones that are from our machine
        if TCP in packet and packet[IP].src != self.local_ip:
            self.detect_port_scanning(packet)
            self.detect_syn_flood(packet)

    # Method which creates the string that represents the packet to be logged
    def stringify_packet(self, packet):
        str_pkt = '\nPacket number {}\n'.format(self.packets_count)
        str_pkt += 'Total packet length: {}\n'.format(len(packet))

        # Data Link level
        str_pkt += '-[Data Link]-\n'
        str_pkt += '  {:<16}  {}\n  {:<16}  {}\n'.format('Source MAC:', packet.src.upper(),
                                                         'Destination MAC:', packet.dst.upper())

        # IP level
        str_pkt += '-[IP]-\n'
        # Get the protocol name from his number
        proto = ''
        if packet[IP].proto == 1:
            proto = 'ICMP'
        elif packet[IP].proto == 6:
            proto = 'TCP'
        elif packet[IP].proto == 17:
            proto = 'UDP'
        str_pkt += '  {:<15}  {}\n  {:<15}  {}\n  {:<15}  {}\n'.format('Source IP:', packet[IP].src,
                                                                       'Destination IP:', packet[IP].dst,
                                                                       'Upper protocol:', proto)

        # TCP, UDP or ICMP level
        if proto == 'ICMP':
            str_pkt += '-[ICMP]-\n'
            str_pkt += '  {:<5}  {}\n  {:<5}  {}\n'.format('Type:', packet[ICMP].type,
                                                           'Code:', packet[ICMP].code)
        elif proto == 'UDP':
            str_pkt += '-[UDP]-\n'
            str_pkt += '  {:<17}  {}\n  {:<17}  {}\n'.format('Source port:', packet[UDP].sport,
                                                             'Destination port:', packet[UDP].dport)
        else:
            flags_dict = \
            {
                'F': 'FIN',
                'S': 'SYN',
                'R': 'RST',
                'P': 'PSH',
                'A': 'ACK',
                'U': 'URG',
                'E': 'ECE',
                'C': 'CWR',
            }

            str_pkt += '-[TCP]-\n'
            str_pkt += '  {:<17}  {}\n  {:<17}  {}\n'.format('Source port:', packet[TCP].sport,
                                                             'Destination port:', packet[TCP].dport)
            flags = ''
            for x in packet.sprintf('%TCP.flags%'):
                flags += '{}, '.format(flags_dict[x])
            str_pkt += '  {:<17}  {}\n'.format('Flags:', flags[:-2])

            # Possible HTTP layer
            if packet.haslayer(HTTP):
                str_pkt += '-[HTTP]-\n'
                if HTTPRequest in packet:
                    # Method and HTTP version
                    str_pkt += '  {:<11}  {}\n  {:<11}  {}\n'.format('Method:', str(packet[HTTPRequest].Method, "ascii"),
                                                                     'Version:', str(packet[HTTPRequest].Http_Version, "ascii"))
                    # Requested URI and Host URI
                    str_pkt += '  {:<11}  {}\n  {:<11}  {}\n'.format('Path:', str(packet[HTTPRequest].Path, "ascii"),
                                                                     'Host:', str(packet[HTTPRequest].Host, "ascii"))
                    # User Agent
                    str_pkt += '  {:<11}  {}\n'.format('User Agent:', str(packet[HTTPRequest].User_Agent, "ascii"))
                elif HTTPResponse in packet:
                    # Status code and phrase
                    str_pkt += '  {:<8}  {} {}\n'.format('Status:', str(packet[HTTPResponse].Status_Code, "ascii"),
                                                         str(packet[HTTPResponse].Reason_Phrase, "ascii"))
                    # HTTP version and server type
                    str_pkt += '  {:<8}  {}\n  {:<8}  {}\n'.format('Version:', str(packet[HTTPResponse].Http_Version, "ascii"),
                                                                   'Server:', str(packet[HTTPResponse].Server, "ascii"))
        return str_pkt

    def detect_port_scanning(self, pkt):
        flags = pkt[TCP].flags
        if flags == 'F':  # TCP FIN scan detection
            if pkt[IP].src not in self.tcp_fin:
                self.tcp_fin[pkt[IP].src] = {"FIN": 0}
            self.tcp_fin[pkt[IP].src]["FIN"] += 1
            self.tcp_fin_scan(pkt)
        elif flags == 'FPU':  # TCP x-Mas scan detection
            if pkt[IP].src not in self.tcp_xmas:
                self.tcp_xmas[pkt[IP].src] = {"FIN-PSH-URG": 0}
            self.tcp_xmas[pkt[IP].src]["FIN-PSH-URG"] += 1
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
            if self.time_first_syn == 0:
                self.time_first_syn = t.time()
            elif t.time() < (self.time_first_syn + self.SYN_FLOOD_DETECT_TIME):
                # If we are here and we detect a huge amount of SYN packets,
                # a SYN Flood attack is may happening.
                self.tcp_syn_count += 1
                if self.tcp_syn_count == self.TCP_SYN_THRESHOLD:
                    print("{} is performing a SYN Flood attack".format(pkt[IP].src))
                    # We want to reset the timer also just after we detect the SYN flood
                    # and not only when the timer elapses
                    self.tcp_syn_count = 0
                    self.time_first_syn = 0
            else:
                # If we are here it means that the timer is elapsed, so we need to reset some attributes
                self.tcp_syn_count = 0
                self.time_first_syn = 0
