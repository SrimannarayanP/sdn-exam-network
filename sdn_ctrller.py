# sdn_ctrller.py


"""
SDN (Software Defined Networking)-Ctrller

How this works: -
    - Handshake (CONFIG_DISPATCHER): When Mininet starts, switch 's1' conns to this script on TCP Port 6633/6653. We install a 'Table-Miss' rule so unknown pkts are
        forwarded to this ctrller instead of being dropped.
    - L2 MAC Learning: As hosts (students h1, ..., h5 exam_server h_server) send ARP/IP pkts, we learn which switch port each MAC address lives on.
    - Deep Pkt Inspection & QoS (Quality of Service) Prioritization: Unlike an L2 switch that only looks at MAC addresses, this ctrller inspects the IPv4 (0x0800) & TCP
        (Proto 6) headers. When it sees traffic on TCP Port 9999 (Exam server port), it installs high-priority (Priority 100) bidirectional OpenFlow rules so exam Qs &
        ans submissions are prioritized over background congestion traffic (Priority 10).
"""


from os_ken.lib import hub


hub.patch(thread = True)


from os_ken.base import app_manager
from os_ken.controller import controller, ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import ether_types, ethernet, ipv4, packet, tcp

import logging


logging.basicConfig(level = logging.INFO, format = "%(asctime)s [%(levelname)s] %(message)s")


class ExamNetworkCtrller(app_manager.OSKenApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION] # Forces the ctrller & OpenVSwitch to use OpenFlow 1.3 for multi-level priorities, QoS queues & meters.

    # Consts
    EXAM_SERVER_PORT = 9999
    PRIORITY_TABLE_MISS = 0 # Lowest priority: Catch-all unknown traffic
    PRIORITY_NORMAL_TRAFFIC = 10 # Std L2 forwarding (e.g. background network noise, pings etc.)
    PRIORITY_EXAM_TRAFFIC = 100 # High priority: Exam server Qs & student ans submissions.
    PRIORITY_SECURITY_DROP = 200 # Unauth-ed host blocked by exam server - Dropped at switch

    QUEUE_BEST_EFFORT = 0
    QUEUE_HIGH_PRIORITY = 1

    def __init__(self, *args, **kwargs):
        super(ExamNetworkCtrller, self).__init__(*args, **kwargs)

        # MAC Learning Table: maps {datapath_id: {'mac_address': switch_port_no}}
        self.mac_to_port = {} 

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
            Triggered automatically once when an Open vSwitch in Mininet finishes its initial handshake with the ctrller (CONFIG_DISPATCHER state).
            By default in OpenFlow 1.3, if a pkt arrives at a switch & matches no rules in the Flow Table, the switch silently drops the pkt. Instead, we install a
            priority 0 rule ('Table-Miss') that tells the switch: "If you don't recognise a flow, send the pkt up to the Python ctrller (OFPP_CONTROLLER) so we can
            inspect it & decide."
        """

        datapath = ev.msg.datapath # Reps the conn-ed OpenFlow switch (e.g. s1)
        ofproto = datapath.ofproto # OpenFlow 1.3 consts (ports, actions, flags) 
        parser = datapath.ofproto_parser
        # Empty OFPMatch() matches every pkt (Priority 0 rule)
        match_miss = parser.OFPMatch()
        # Send the full pkt to the ctrller
        actions_ctrl = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        # Set priority to 0
        self.add_flow(datapath, self.PRIORITY_TABLE_MISS, match_miss, actions_ctrl)

        # Priority 50 intercept rules for TCP port 9999 so priority 10 never shadows exam auth.
        for field in ({'tcp_dst': self.EXAM_SERVER_PORT}, {'tcp_src': self.EXAM_SERVER_PORT}):
            match_exam = parser.OFPMatch(eth_type = ether_types.ETH_TYPE_IP, ip_proto = 6, **field)
            self.add_flow(datapath, 50, match_exam, actions_ctrl)

        self.logger.info("[INIT] Switch s%s conn-ed (OpenFlow 1.3). Table-Miss rule installed.", datapath.id)

    # Helper func to push rules to the switch kernel table
    def add_flow(self, datapath, priority, match, actions, buffer_id = None, idle_timeout = 0):
        """
            Constucts an OpenFlow FlowMod (Flow Modification) msg & sends it to the switch to prog a rule into its flow table. Once a rule is installed in the switch via
            add_flow(), future pkts matching `match` are forwarded directly in the Linux kernel by Open vSwitch at line rate without waking up this Py script again.

            Params:
                datapath: Target switch obj.
                priority: Higher no. = Higher precedence in the switch table.
                match: OFPMatch obj specifying pkt headers (MAC, IP, TCP port).
                actions: List of OFPAction objs (which port/queue to send to, or empty to drop).
                buffer_id: ID of pkt buffered on the switch (if any).
                idle_timeout: Seconds of inactivity before the switch auto-deletes the rule (0 = permanent).
        """

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id is not None:
            mod = parser.OFPFlowMod(datapath = datapath, buffer_id = buffer_id, idle_timeout = idle_timeout, priority = priority, match = match, instructions = inst)
        else:
            mod = parser.OFPFlowMod(datapath = datapath, idle_timeout = idle_timeout, priority = priority, match = match, instructions = inst)

        datapath.send_msg(mod) # Send the rule over the OpenFlow ctrl channel to the switch.

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def pkt_in_handler(self, ev):
        """
            Triggered whenever the switch receives a pkt that doesn't match any existing flow rule (hitting the Priority 0 Table-Miss rule).
            - Unpack raw Bs into ethernet, IPv4 & TCP headers.
            - Record the sender's MAC address & incoming switch port.
            - Check if dest MAC is known; if not, flood (for ARP discovery).
            - Inspect Layer 4 (TCP). If it's exam traffic (port 9999), install a Priority 100 rule. If it's normal traffic, install a Priority 10 rule.
            - Send the curr pkt out the target port so it isn't lost.
        """

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Physical port on the switch where the pkt entered.
        in_port = msg.match['in_port']
        # Parse the raw bin pkt payload into protocol layers.
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP: return # Skip LLDP (Link Layer Discovery Protocol) frames used by topology discovery.

        dst_mac = eth.dst
        src_mac = eth.src
        dpid = datapath.id

        # L2 MAC Address Learning
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        # Determine output switch port
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            # Dest MAC unknown (usually the 1st ARP broadcast): flood all ports
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Check IPv4 & TCP headers when output port is known.
        if out_port != ofproto.OFPP_FLOOD:
            # Extract IPv4 & TCP headers if present inside the frame.
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            tcp_pkt = pkt.get_protocol(tcp.tcp)

            is_exam_traffic = (ip_pkt is not None and tcp_pkt is not None and (tcp_pkt.dst_port == self.EXAM_SERVER_PORT or tcp_pkt.src_port == self.EXAM_SERVER_PORT))

            if is_exam_traffic:
                raw_payload = msg.data.decode('utf-8', errors = 'ignore') # Extract raw TCP payload (if any) to inspect Exam Server AUTH_OK/AUTH_FAIL events.

                # Client failed all 3 login attempts -> Server sent 'SDN_BLOCK_HOST'
                if 'SDN_BLOCK_HOST' in raw_payload:
                    rogue_ip = ip_pkt.dst # Server -> Rogue Client res

                    self.logger.warning("[SDN-SECURITY] Exam server rejected unauth-ed host %s. Installing Priority %d OpenFlow DROP rule on Switch s%s.", rogue_ip, self.PRIORITY_SECURITY_DROP, dpid)

                    drop_match = parser.OFPMatch(eth_type = ether_types.ETH_TYPE_IP, ipv4_src = rogue_ip)

                    # actions = [] drops all future pkts from rogue_ip at switch edge.
                    self.add_flow(datapath, self.PRIORITY_SECURITY_DROP, drop_match, actions = [], idle_timeout = 120)
                # Legit student auth-ed -> Server sent 'AUTH_OK'
                elif 'AUTH_OK' in raw_payload:
                    student_ip = ip_pkt.dst # Pkt is travelling from server -> student
                    server_ip = ip_pkt.src
                    student_port = tcp_pkt.dst_port
                    server_port = tcp_pkt.src_port

                    self.logger.info("[SDN-QOS] Student %s verified ('AUTH-OK'). Installing bidirectional Priority %d + High-Priority Queue %d rules for TCP Port %d", student_ip, self.PRIORITY_EXAM_TRAFFIC, self.QUEUE_HIGH_PRIORITY, self.EXAM_SERVER_PORT)

                    # Server -> student (Q delivery, timer sync, grades)
                    match_s2c = parser.OFPMatch(
                        eth_type = ether_types.ETH_TYPE_IP,
                        ipv4_src = server_ip,
                        ipv4_dst = student_ip,
                        ip_proto = 6,
                        tcp_src = server_port,
                        tcp_dst = student_port
                    )

                    actions_s2c = [parser.OFPActionSetQueue(self.QUEUE_HIGH_PRIORITY), parser.OFPActionOutput(out_port)]
                    self.add_flow(datapath, self.PRIORITY_EXAM_TRAFFIC, match_s2c, actions_s2c, idle_timeout = 60)

                    match_c2s = parser.OFPMatch(
                        eth_type = ether_types.ETH_TYPE_IP,
                        ipv4_src = student_ip,
                        ipv4_dst = server_ip,
                        ip_proto = 6,
                        tcp_src = student_port,
                        tcp_dst = server_port
                    )

                    actions_c2s = [parser.OFPActionSetQueue(self.QUEUE_HIGH_PRIORITY), parser.OFPActionOutput(in_port)]
                    self.add_flow(datapath, self.PRIORITY_EXAM_TRAFFIC, match_c2s, actions_c2s, idle_timeout = 60)

                # For TCP SYN/ACK pkts & AUTH_RETRY warnings (typos), neither branch triggers, so the pkt simply forwards via PacketOut without blocking.
            else:
                actions = [parser.OFPActionSetQueue(self.QUEUE_BEST_EFFORT), parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port = in_port, eth_dst = dst_mac, eth_src = src_mac)

                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, self.PRIORITY_NORMAL_TRAFFIC, match, actions, msg.buffer_id, idle_timeout = 30)

                    return
                else:
                    self.add_flow(datapath, self.PRIORITY_NORMAL_TRAFFIC, match, actions, idle_timeout = 30)

        data = None

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath = datapath, buffer_id = msg.buffer_id, in_port = in_port, actions = actions, data = data)
        datapath.send_msg(out)


if __name__ == '__main__':
    print("[SDN-CTRLLER] Booting OS-Ken OpenFlow 1.3 Ctrller on 0.0.0.0:6633/6653...")

    app_mgr = app_manager.AppManager.get_instance()
    app_mgr.load_apps(['sdn_ctrller'])
    contexts = app_mgr.create_contexts()
    services = app_mgr.instantiate_apps(**contexts)

    # Start the OpenFlow TCP listening server on 0.0.0.0:6633/6653
    ofp_ctrl = controller.OpenFlowController()
    services.append(hub.spawn(ofp_ctrl))

    print("[SDN-CTRLLER] Ready & waiting for Mininet switch s1 to conn...")

    try:
        hub.joinall(services)
    except KeyboardInterrupt:
        app_mgr.close()