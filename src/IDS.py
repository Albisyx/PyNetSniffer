import os
import logging
import datetime
import time as t
from scapy.layers.inet import *
from scapy.layers.http import *
from scapy.layers.dns import *
from socket import gethostname, gethostbyname


# Class that implements the intrusion detection capabilities.
# The two attacks that will be detected are:
# 1) Port scanning attempts
#    The following port scans attempts will be detected:
#    - TCP FIN port scanning
#    - TCP X-Mas port scanning
# 2) SYN Flood attack


class Detector:
    def __init__(self):
        self.log_path = '/var/log/PyNetSniffer/'         # default path for the log files
        self.packets_logger = self.get_packets_logger()  # packet's info logger
        self.ids_logger = self.get_ids_logger()          # IDS's warnings logger
        self.tcp_fin = dict()                            # dictionary that contains IP addresses and their related
                                                         # number of FIN packets sent
        self.tcp_xmas = dict()                           # dictionary that contains IP addresses and their related
                                                         # number of FIN-PSH-URG packets sent
        self.local_ip = gethostbyname(gethostname())     # host IP address
        self.time_first_syn = 0                          # timestamp of the first TCP SYN packet encountered
        self.tcp_syn_count = 0                           # counter of TCP SYN packets received
        self.packets_count = 0                           # simple counter of all the sniffed packets
        self.PORT_SCAN_THRESHOLD = 500                   # number of FIN-PSH-URG packets after which a warning is generated
        self.TCP_SYN_THRESHOLD = 500                     # number of SYN packets after which a warning is generated
        self.SYN_FLOOD_DETECT_TIME = 3                   # number of seconds within a SYN Flood attack is detected

    # The following method is called whenever a packet is sniffed on the selected
    # interface. It initializes the process of attacks detection.
    # It also performs the packets logging to a file.
    def inspect_packets(self, packet):
        # First we have to ignore packets that don't contain an IP header
        if IP not in packet:
            return

        # Let's also discard all packets that are not TCP, UDP or ICMP
        if TCP not in packet and \
           UDP not in packet and \
           ICMP not in packet:
            return

        # At this point we have a packet which for sure has an IP header
        # and it contains TCP, UDP or ICMP segment.

        self.packets_count += 1

        # Here we log the current packet to a file
        self.packets_logger.debug(self.stringify_packet(packet))

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

        # Data Link layer
        str_pkt += '-[Data Link]-\n'
        str_pkt += '  {:<16}  {}\n  {:<16}  {}\n'.format('Source MAC:', packet.src.upper(),
                                                         'Destination MAC:', packet.dst.upper())

        # IP layer
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

        # TCP, UDP or ICMP layer
        if proto == 'ICMP':
            str_pkt += '-[ICMP]-\n'
            str_pkt += '  {:<5}  {}\n  {:<5}  {}\n'.format('Type:', packet[ICMP].type,
                                                           'Code:', packet[ICMP].code)
        elif proto == 'UDP':
            str_pkt += '-[UDP]-\n'
            str_pkt += '  {:<17}  {}\n  {:<17}  {}\n'.format('Source port:', packet[UDP].sport,
                                                             'Destination port:', packet[UDP].dport)

            # Possible DNS layer
            # Simplified information regarding DNS
            if packet.haslayer(DNS):
                str_pkt += '-[DNS]-\n'
                if not packet[DNS].qr:  # This is a DNS query
                    str_pkt += '  {:<12}  {}\n'.format('Query name:', str(packet[DNS].qd[0].qname, "ascii")[:-1])
                    # Getting query type from decimal ID
                    query_type = ''
                    if packet[DNS].qd[0].qtype == 1:
                        query_type = 'A'
                    elif packet[DNS].qd[0].qtype == 2:
                        query_type = 'NS'
                    elif packet[DNS].qd[0].qtype == 5:
                        query_type = 'CNAME'
                    elif packet[DNS].qd[0].qtype == 12:
                        query_type = 'PTR'
                    str_pkt += '  {:<12}  {}\n'.format('Query type:', query_type)
                    # Getting query class from decimal ID
                    query_class = ''
                    if packet[DNS].qd[0].qclass == 1:
                        query_class = 'IN'
                    str_pkt += '  {:<12}  {}\n'.format('Query class:', query_class)
                else:  # This is a DNS response
                    if packet[DNS].ancount > 0:
                        # If we are here it means that we have at least a normal answer
                        dns_answer = packet[DNS].an[0]
                    else:
                        # If we are here it means that we only have an authority answer
                        dns_answer = packet[DNS].ns[0]

                    str_pkt += '  {:<13}  {}\n'.format('Answer name:', str(dns_answer.rrname, "ascii")[:-1])
                    # Getting answer type from decimal ID
                    answer_type = ''
                    if dns_answer.type == 1:
                        answer_type = 'A'
                    elif dns_answer.type == 2:
                        answer_type = 'NS'
                    elif dns_answer.type == 5:
                        answer_type = 'CNAME'
                    elif dns_answer.type == 12:
                        answer_type = 'PTR'
                    str_pkt += '  {:<13}  {}\n'.format('Answer type:', answer_type)
                    # Getting answer class from decimal ID
                    answer_class = ''
                    if dns_answer.rclass == 1:
                        answer_class = 'IN'
                    str_pkt += '  {:<13}  {}\n'.format('Answer class:', answer_class)
        else:  # TCP layer
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
            
            # Get the full flag name using the above dictionary
            flags = ''
            for x in packet.sprintf('%TCP.flags%'):
                flags += '{}, '.format(flags_dict[x])
            str_pkt += '  {:<17}  {}\n'.format('Flags:', flags[:-2])

            # Possible HTTP layer
            if packet.haslayer(HTTP):
                str_pkt += '-[HTTP]-\n'
                if HTTPRequest in packet:
                    # Method and HTTP version
                    str_pkt += '  {:<11}  {}\n  {:<11}  {}\n'.format('Method:',
                                                                     str(packet[HTTPRequest].Method, "ascii"),
                                                                     'Version:',
                                                                     str(packet[HTTPRequest].Http_Version, "ascii"))
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
                    str_pkt += '  {:<8}  {}\n  {:<8}  {}\n'.format('Version:',
                                                                   str(packet[HTTPResponse].Http_Version, "ascii"),
                                                                   'Server:', str(packet[HTTPResponse].Server, "ascii"))
        return str_pkt

    # The following 3 methods are used for detecting port scanning attempts
    def detect_port_scanning(self, pkt):
        flags = pkt[TCP].flags
        if flags == 'F':  # TCP FIN scan detection
            if pkt[IP].src not in self.tcp_fin:
                self.tcp_fin[pkt[IP].src] = {"FIN": 0}
            self.tcp_fin[pkt[IP].src]["FIN"] += 1
            self.tcp_fin_scan(pkt[IP].src)
        elif flags == 'FPU':  # TCP x-Mas scan detection
            if pkt[IP].src not in self.tcp_xmas:
                self.tcp_xmas[pkt[IP].src] = {"FIN-PSH-URG": 0}
            self.tcp_xmas[pkt[IP].src]["FIN-PSH-URG"] += 1
            self.tcp_xmas_scan(pkt[IP].src)

    def tcp_fin_scan(self, source_ip):
        for ip in self.tcp_fin.keys():
            if self.tcp_fin[ip]["FIN"] > self.PORT_SCAN_THRESHOLD:
                log = "{} has sent you a relevant number of FIN packets.\n".format(source_ip)
                log += "A FIN port scanning is probably happening...\n"
                log += "The packet that triggered this alert is the number {}\n".format(self.packets_count)
                # Let's log the warning both to a file and on the console
                self.ids_logger.warning(log)
                # Reset the FIN count
                self.tcp_fin[ip]["FIN"] = 0

    def tcp_xmas_scan(self, source_ip):
        for ip in self.tcp_xmas.keys():
            if self.tcp_xmas[ip]["FIN-PSH-URG"] > self.PORT_SCAN_THRESHOLD:
                log = "{} has sent you a relevant number of FIN-PSH-URG packets.\n".format(source_ip)
                log += "A X-Mas port scanning is probably happening...\n"
                log += "The packet that triggered this alert is the number {}\n".format(self.packets_count)
                # Let's log the warning both to a file and on the console
                self.ids_logger.warning(log)
                # Reset the FIN-PSH-URG count
                self.tcp_xmas[ip]["FIN-PSH-URG"] = 0

    # This method tries to detect a SYN Flood attack by using an interval of time.
    # Basically it starts a timer when the first TCP SYN packet is encountered.
    # If it detect a large number of SYN packets before the timer is elapsed, a SYN Flood attack is may happening.
    def detect_syn_flood(self, pkt):
        if pkt[TCP].flags == 'S':
            if self.time_first_syn == 0:
                self.time_first_syn = t.time()
            elif t.time() < (self.time_first_syn + self.SYN_FLOOD_DETECT_TIME):
                # If we are here and we detect a huge amount of SYN packets,
                # a SYN Flood attack is may happening.
                self.tcp_syn_count += 1
                if self.tcp_syn_count == self.TCP_SYN_THRESHOLD:
                    log = "In the past {} seconds you received a ".format(self.SYN_FLOOD_DETECT_TIME)
                    log += "considerable number of SYN packet from {}\n".format(pkt[IP].src)
                    log += "A SYN Flood attack is probably happening...\n"
                    log += "The packet that triggered this alert is the number {}\n".format(self.packets_count)
                    # Let's log the warning both to a file and on the console
                    self.ids_logger.warning(log)
                    # We want to reset the timer also just after we detect the SYN Flood
                    # and not only when the timer elapses
                    self.tcp_syn_count = 0
                    self.time_first_syn = 0
            else:
                # If we are here it means that the timer is elapsed without detecting any attack,
                # so we need to reset some attributes
                self.tcp_syn_count = 0
                self.time_first_syn = 0

    # Method that configures the logger used to store packets informations
    def get_packets_logger(self):
        packets_logger = logging.getLogger("pcap")
        packets_logger.setLevel(logging.DEBUG)

        # Creation of the FileHandler in order to log packets to a file
        current_datetime = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        # The default path used to save log file is /var/log/PyNetSniffer/
        # Check if we have all the directories needed
        if not os.path.exists(self.log_path):
            os.makedirs(self.log_path)
        file_logs = logging.FileHandler(f"{self.log_path}captured_packets_{current_datetime}.txt")
        file_logs_format = logging.Formatter("%(asctime)s:%(levelname)s: %(message)s")
        file_logs.setFormatter(file_logs_format)

        # Creation of the StreamHandler in order to log packets on the console
        console_logs = logging.StreamHandler()
        # Setting a different logging level for the console
        console_logs.setLevel(logging.INFO)

        # Adding the handlers just created
        packets_logger.addHandler(file_logs)
        packets_logger.addHandler(console_logs)

        return packets_logger

    # Method that configure the logger used to store IDS warnings
    def get_ids_logger(self):
        ids_logger = logging.getLogger("ids")
        ids_logger.setLevel(logging.WARNING)

        # Creation of the FileHandler in order to log detected attacks to a file
        current_datetime = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        file_logs = logging.FileHandler(f"{self.log_path}attacks_detected_{current_datetime}.txt")
        file_logs_format = logging.Formatter("%(asctime)s:%(levelname)s: %(message)s")
        file_logs.setFormatter(file_logs_format)

        # Creation of the StreamHandler in order to log detected attacks on the console
        console_logs = logging.StreamHandler()

        # Adding the handlers just created
        ids_logger.addHandler(file_logs)
        ids_logger.addHandler(console_logs)

        return ids_logger
