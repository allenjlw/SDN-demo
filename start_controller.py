from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

from ryu.ofproto import ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import icmp
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu import utils


class SimpleController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        self.datapaths = {}
        super(SimpleController, self).__init__(*args, **kwargs)

    def add_flow(self, datapath, match, actions, priority, hard_timeout=0):
        # 1. The 'match' indicates the target packet conditions
        # 2. The 'instruction' indicates the operations on the packet, entry priority
        # level, and effective time
        # 3. Controller sends the 'OFPFlowMod' message to modify flow table
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = ofp_parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    hard_timeout=hard_timeout,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def clear_flows(self, datapath, initialize=False):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        clear_msg = ofp_parser.OFPFlowMod(
                        datapath=datapath,
                        table_id=ofp.OFPTT_ALL,
                        command=ofp.OFPFC_DELETE,
                        out_port=ofp.OFPP_ANY,
                        out_group=ofp.OFPG_ANY)
        datapath.send_msg(clear_msg)

        if initialize:
            match = ofp_parser.OFPMatch(eth_type=0x800, ip_proto=252)
            actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, match=match, actions=actions, priority=10)

            match = ofp_parser.OFPMatch(eth_type=0x800, ip_proto=253)
            actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, match=match, actions=actions, priority=10)

            match = ofp_parser.OFPMatch(eth_type=0x800, ip_proto=254)
            actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, match=match, actions=actions, priority=10)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def on_state_change(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.info('Register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info('Unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def on_switch_features(self, ev):
        datapath = ev.msg.datapath
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        self.logger.info("Switch: %s Connected", datapath.id)

        if datapath.id == 1:
            self.clear_flows(datapath, initialize=True)
        else:
            self.clear_flows(datapath)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def on_packet_in(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofp_parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocols(ethernet.ethernet)[0]
        icmp_pkt = pkt.get_protocols(icmp.icmp)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        ip_pkt_6 = pkt.get_protocol(ipv6.ipv6)

        if isinstance(ip_pkt, ipv4.ipv4):
            clear = ip_pkt.src == '10.0.1.1' and ip_pkt.dst == '10.0.2.1' and ip_pkt.proto == 252
            default = ip_pkt.src == '10.0.1.1' and ip_pkt.dst == '10.0.2.1' and ip_pkt.proto == 253
            alternative = ip_pkt.src == '10.0.1.1' and ip_pkt.dst == '10.0.2.1' and ip_pkt.proto == 254
            
            if default:
                self.logger.info('Installing DEFAULT rules: h1 <-> s1 <-> s2 <-> h2')

                self.clear_flows(self.datapaths[1], initialize=True)
                self.clear_flows(self.datapaths[2])
                self.clear_flows(self.datapaths[3])

                match = ofp_parser.OFPMatch(eth_type=0x800, ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst)
                actions = [ofp_parser.OFPActionOutput(2)]
                self.add_flow(self.datapaths[1], match=match, actions=actions, priority=1)
                
                match = ofp_parser.OFPMatch(eth_type=0x800, ipv4_src=ip_pkt.dst, ipv4_dst=ip_pkt.src)
                actions = [ofp_parser.OFPActionOutput(1)]
                self.add_flow(self.datapaths[1], match=match, actions=actions, priority=1)

                match = ofp_parser.OFPMatch(eth_type=0x800, ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst)
                actions = [ofp_parser.OFPActionOutput(1)]
                self.add_flow(self.datapaths[2], match=match, actions=actions, priority=1)
                
                match = ofp_parser.OFPMatch(eth_type=0x800, ipv4_src=ip_pkt.dst, ipv4_dst=ip_pkt.src)
                actions = [ofp_parser.OFPActionOutput(2)]
                self.add_flow(self.datapaths[2], match=match, actions=actions, priority=1)
            
            if alternative:
                self.logger.info('Installing ALTERNATIVE rules: h1 <-> s1 <-> s3 <-> s2 <-> h2')
                self.clear_flows(self.datapaths[1], initialize=True)
                self.clear_flows(self.datapaths[2])
                self.clear_flows(self.datapaths[3])

                match = ofp_parser.OFPMatch(eth_type=0x800, ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst)
                actions = [ofp_parser.OFPActionOutput(3)]
                self.add_flow(self.datapaths[1], match=match, actions=actions, priority=1)
                
                match = ofp_parser.OFPMatch(eth_type=0x800, ipv4_src=ip_pkt.dst, ipv4_dst=ip_pkt.src)
                actions = [ofp_parser.OFPActionOutput(1)]
                self.add_flow(self.datapaths[1], match=match, actions=actions, priority=1)

                match = ofp_parser.OFPMatch(eth_type=0x800, ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst)
                actions = [ofp_parser.OFPActionOutput(1)]
                self.add_flow(self.datapaths[2], match=match, actions=actions, priority=1)
                
                match = ofp_parser.OFPMatch(eth_type=0x800, ipv4_src=ip_pkt.dst, ipv4_dst=ip_pkt.src)
                actions = [ofp_parser.OFPActionOutput(3)]
                self.add_flow(self.datapaths[2], match=match, actions=actions, priority=1)

                match = ofp_parser.OFPMatch(eth_type=0x800, ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst)
                actions = [ofp_parser.OFPActionOutput(1)]
                self.add_flow(self.datapaths[3], match=match, actions=actions, priority=1)
                
                match = ofp_parser.OFPMatch(eth_type=0x800, ipv4_src=ip_pkt.dst, ipv4_dst=ip_pkt.src)
                actions = [ofp_parser.OFPActionOutput(2)]
                self.add_flow(self.datapaths[3], match=match, actions=actions, priority=1)

            if clear:
                self.logger.info('Clearing rules')
                self.clear_flows(self.datapaths[1], initialize=True)
                self.clear_flows(self.datapaths[2])
                self.clear_flows(self.datapaths[3])