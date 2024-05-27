from scapy.all import (Ether, sendp, Raw, IPv6, Packet, BitField, ByteField, ShortField, IntField, sniff, bind_layers, PacketListField)

class Matadata(Packet):
	name = "Matadata_Row"
	fields_desc = [
		ByteField("switch_id", 0),
		ShortField("queue_latency", 0)
	]
	def guess_payload_class(self, payload):
		if len(payload) >= 24:
			return Matadata
		else:
			return Packet.guess_payload_class(self, payload)

class INTHeaderBeginning(Packet):
	name = "INTHeaderBeginning"
	fields_desc = [
		BitField("ver", 0, 4),
		BitField("flags", 0, 2),
		BitField("M", 0, 1),
		BitField("reserved", 0, 1),
		BitField("hop_ml", 0, 5),
		BitField("remaining_hop_cnt", 0, 8),
		BitField("instruction_bitmap", 0, 11),
		PacketListField("matadata", None, Matadata, count_from=lambda pkt:pkt.hop_ml)
	]

bind_layers(Ether, INTHeaderBeginning, type=0x7FFF)
bind_layers(INTHeaderBeginning, IPv6)

#bind_layers(INTHeaderBeginning, Matadata)

#bind_layers(INTHeaderBeginning, Matadata2, hop_ml=2)

sendp(Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00')/INTHeaderBeginning(hop_ml=1)/Matadata()/IPv6(dst="0000:0000:0000:0000:0000:0000:0000:0002"), iface='h1-eth1')
#IPv6(dst="2001:db8::1")
	
sniff(iface='s1-eth3')
a=_
a.nsummary()
a[0]