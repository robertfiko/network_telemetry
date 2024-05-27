from scapy.all import (Ether, sendp, Raw, IPv6, Packet, BitField, ByteField, ShortField, IntField, sniff, bind_layers, PacketListField, DestIP6Field, AsyncSniffer)

class Matadata(Packet):
	name = "Matadata_Row"
	fields_desc = [
		ByteField("switch_id", 0),
		BitField("in_port_id", 0, 9),
		BitField("e_port_id", 0, 9),
		BitField("processed_time", 0, 48),
		BitField("padding", 0, 6),
	]
	def extract_padding(self, s):
		return '', s

class INT(Packet):
	name = "INT"
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

class SRH_segment(Packet):
	name = "SRH segment"
	fields_desc = [
		DestIP6Field("dst", "::1")
	]
	def extract_padding(self, s):
		return '', s

class SRH(Packet):
	name = "SRH"
	fields_desc = [
		ByteField("next_header", 0),
		ByteField("hdr_ext_len", 0),
		ByteField("routing_type", 0),
		ByteField("segments_left", 0),
		ByteField("last_entry", 0),
		ByteField("flags", 0),
		ShortField("tag", 0),
		PacketListField("segments", None, SRH_segment, count_from=lambda pkt:pkt.segments_left)
	]

bind_layers(Ether, INT, type=0x7FFF)
bind_layers(INT, IPv6)
bind_layers(IPv6, SRH, nh=43)
bind_layers(IPv6, INT, nh=253)

#sendp(Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00')/INT(hop_ml=1)/Matadata()/IPv6(dst="0000:0000:0000:0000:0000:0000:0000:0002"), iface='h1-eth1')
#sendp(Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00')/INT(hop_ml=1)/Matadata()/IPv6(dst="::1")/SRH(segments_left=1)/SRH_segment(dst="::2"), iface='h1-eth1')
sendp(Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00')/INT(hop_ml=1)/Matadata()/IPv6(dst="::2")/SRH(segments_left=1)/SRH_segment(dst="::0001:0001"), iface='h1-eth1')
sendp(Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00')/INT(hop_ml=1, instruction_bitmap=0b11111111111)/Matadata()/IPv6(dst="::2")/SRH(segments_left=3)/SRH_segment(dst="::0001:0001")/SRH_segment(dst="::0001:0006")/SRH_segment(dst="::0001:0003"), iface='h1-eth1')

#sniff(iface='s1-eth3')
sniff(iface='h2-eth1')
a=_
a.nsummary()
a[0]