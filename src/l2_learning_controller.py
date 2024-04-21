import nnpy
import struct
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from scapy.all import Ether, sniff, Packet, BitField, raw


class CpuHeader(Packet):
    name = 'CpuPacket'
    fields_desc = [BitField('macAddr',0,48), BitField('ingress_port', 0, 16)]


class L2Controller(object):

    def __init__(self, sw_name):
        self.topo = load_topo('topology.json')
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.cpu_port =  self.topo.get_cpu_port_index(self.sw_name)
        self.controller = SimpleSwitchThriftAPI(self.thrift_port)
        self.init()

    def init(self):
        self.controller.reset_state()
        self.add_boadcast_groups()
        self.add_mirror()

    def add_mirror(self):
        if self.cpu_port:
            self.controller.mirroring_add(100, self.cpu_port)

    def add_boadcast_groups(self):
        interfaces_to_port = self.topo.get_node_intfs(fields=['port'])[self.sw_name].copy()
        # Filter lo and cpu port
        interfaces_to_port.pop('lo', None)
        interfaces_to_port.pop(self.topo.get_cpu_port_intf(self.sw_name), None)

        mc_grp_id = 1
        rid = 0
        for ingress_port in interfaces_to_port.values():
            port_list = list(interfaces_to_port.values())
            del(port_list[port_list.index(ingress_port)])
            #add multicast group
            self.controller.mc_mgrp_create(mc_grp_id)
            #add multicast node group
            handle = self.controller.mc_node_create(rid, port_list)
            #associate with mc grp
            self.controller.mc_node_associate(mc_grp_id, handle)
            #fill broadcast table
            self.controller.table_add("broadcast", "set_mcast_grp", [str(ingress_port)], [str(mc_grp_id)])
            mc_grp_id +=1
            rid +=1

    def learn(self, learning_data):
        for mac_addr, ingress_port in  learning_data: #ez azért van, mert a dp-n a digestnél egyedileg betettük a macet és a portot, de maga a rendszer lehet, hogy blokkosítja ezt és batchekben küldi fel, ha túl gyakran küldünk digestet, akkor az lehet hogy "tüzelni fog", batchekben jönnek meg a digestek, nem egyedi üzenetenként mennek fel, mert annak túl nagy lenne az overheadje
            print("mac: %012X ingress_port: %s " % (mac_addr, ingress_port))
            #TODO: Add an entry to smac
            self.controller.table_add("smac", "NoAction", [str(mac_addr)]) #maga a táblanév az első paraméter, a második az akció, a harmadik pedig egy páros (vagyis a matching key, a kulcs, amire illeszkedni kell, az értékkel), ként még paraméterlista, de olyan most nincs, ezért hagyhatjuk üresen
            #TODO: Add an entry to dmac
            self.controller.table_add("dmac", "forward", [str(mac_addr)], [str(ingress_port)])
            #HINT: table_add(table_name, action_name, list of matches, list of action parameters)

    def unpack_digest(self, msg, num_samples):
        digest = []
        starting_index = 32
        for sample in range(num_samples):
            mac0, mac1, ingress_port = struct.unpack(">LHH", msg[starting_index:starting_index+8])
            starting_index +=8
            mac_addr = (mac0 << 16) + mac1
            digest.append((mac_addr, ingress_port))

        return digest

    def recv_msg_digest(self, msg):
        topic, device_id, ctx_id, list_id, buffer_id, num = struct.unpack("<iQiiQi",
                                                                          msg[:32])
        digest = self.unpack_digest(msg, num)
        self.learn(digest) #a digest egy struktúra, amibe mi rakjuk bele az infót, ez egy üzenetként megy fel
        #amit feldolgozunk és az alapján beszúrjuk a dolgokat
        #2 dolgot tartlmaz a digest: a mac címet (48 bit) és az ingress portot (9 bit)
        #erre már ez fel van készítve a learn-ben
        #Acknowledge digest
        self.controller.client.bm_learning_ack_buffer(ctx_id, list_id, buffer_id)


    def run_digest_loop(self):
        sub = nnpy.Socket(nnpy.AF_SP, nnpy.SUB)
        notifications_socket = self.controller.client.bm_mgmt_get_info().notifications_socket
        #print(notifications_socket)
        sub.connect(notifications_socket)
        sub.setsockopt(nnpy.SUB, nnpy.SUB_SUBSCRIBE, '')
        while True:
            msg = sub.recv()
            self.recv_msg_digest(msg)


if __name__ == "__main__":
    import sys
    sw_name = sys.argv[1]
    receive_from = sys.argv[2]
    if receive_from == "digest":
        controller = L2Controller(sw_name).run_digest_loop()
    else:
        print("nem jó")