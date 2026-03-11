import json
import time
import eventlet
from collections import defaultdict


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import tcp
from ryu.lib.packet import arp
from ryu.ofproto import ofproto_v1_0, ofproto_v1_3

from network.load_balancer import RoundRobinLoadBalancer
from security.bruteforce_detector import BruteForceDetector
from security.ddos_detector import DDoSDetector
from utils.logger import security_logger



class AntiBruteForceSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION, ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AntiBruteForceSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.host_index = {}
        self.blocked_ips = set()
        self.switch_packet_count = defaultdict(int)
        self.total_packet_count = 0
        self.total_byte_count = 0
        self.started_at = time.time()

        self.SSH_PORT = 22
        self.THRESHOLD = 5
        self.WINDOW = 30
        self.BLOCK_TIME = 60
        self.DDOS_THRESHOLD_PPS = 1000
        self.LOAD_BALANCER_VIP = "10.0.0.100"

        self.bruteforce_detector = BruteForceDetector(
            threshold=self.THRESHOLD,
            window_seconds=self.WINDOW,
            block_time=self.BLOCK_TIME,
        )
        self.ddos_detector = DDoSDetector(
            packets_per_second_threshold=self.DDOS_THRESHOLD_PPS,
            window_seconds=1.0,
        )
        self.load_balancer = RoundRobinLoadBalancer(
            servers=[
                {"name": "server-1", "ip": "10.0.0.2", "port": 2},
                {"name": "server-2", "ip": "10.0.0.3", "port": 3},
            ]
        )
        self.sec_logger = security_logger

        # Start custom raw socket REST API in background
        hub.spawn(self._start_custom_rest_server)

        self.sec_logger.log_event(
            "controller",
            "Anti-Brute-Force Shield Active with Eventlet API",
            details={"versions": ["OpenFlow1.3", "OpenFlow1.0"]},
        )

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath
        self.sec_logger.log_event(
            "switch_connected",
            "Switch connected to controller",
            details={"dpid": datapath.id, "of_version": datapath.ofproto.OFP_VERSION},
        )

        if datapath.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, 0, match, actions)
        else:
            match = parser.OFPMatch()
            # OVS 1.11.0 on legacy VM doesn't handle OFPActionOutput byte limits gracefully from Python structs.
            # Using bare minimum implementation for OF 1.0 Table-miss.
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
            self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if datapath.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                    instructions=inst, hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, match=match, cookie=0,
                                    command=ofproto.OFPFC_ADD, priority=priority,
                                    actions=actions, hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    def block_ip(self, src_ip, duration=120, reason="manual"):
        for datapath in self.datapaths.values():
            parser = datapath.ofproto_parser
            if datapath.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
            else:
                src_ip_int = self.bruteforce_detector._ip_to_int(src_ip)
                match = parser.OFPMatch(dl_type=0x0800, nw_src=src_ip_int)
            self.add_flow(datapath, 120, match, [], hard_timeout=duration)

        self.blocked_ips.add(src_ip)
        eventlet.spawn_after(duration, self.blocked_ips.discard, src_ip)
        self.sec_logger.log_event(
            "blocked_ip",
            "Manually blocked source IP",
            severity="warning",
            details={"ip": src_ip, "duration": duration, "reason": reason},
        )

    def enable_load_balancer(self):
        self.load_balancer.enable()
        self.sec_logger.log_event("load_balance", "Load balancer enabled")

    def disable_load_balancer(self):
        self.load_balancer.disable()
        self.sec_logger.log_event("load_balance", "Load balancer disabled")

    @staticmethod
    def _format_event(event):
        rendered = dict(event)
        timestamp = float(rendered.get("timestamp", 0))
        rendered["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
        return rendered

    def get_status(self):
        elapsed = max(time.time() - self.started_at, 1)
        bandwidth_mbps = (self.total_byte_count * 8.0) / elapsed / 1000000.0

        connected_hosts = []
        for mac, host in self.host_index.items():
            connected_hosts.append(
                {
                    "mac": mac,
                    "ip": host.get("ip"),
                    "switch": host.get("switch"),
                    "in_port": host.get("in_port"),
                    "last_seen": time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime(host.get("last_seen", time.time()))
                    ),
                }
            )

        switch_stats = []
        for dpid, count in self.switch_packet_count.items():
            switch_stats.append({"dpid": dpid, "packet_count": count})

        load_servers = self.load_balancer.get_servers()
        return {
            "connected_hosts": connected_hosts,
            "switch_statistics": switch_stats,
            "traffic_statistics": {
                "packet_count": self.total_packet_count,
                "byte_count": self.total_byte_count,
                "bandwidth_mbps": round(bandwidth_mbps, 3),
                "rates_per_ip": self.ddos_detector.get_rates(),
            },
            "blocked_ip_list": sorted(self.blocked_ips),
            "detected_attacks": [
                self._format_event(event)
                for event in self.sec_logger.get_recent_attacks(limit=100)
            ],
            "alerts": [
                self._format_event(event)
                for event in self.sec_logger.get_recent_events(limit=100)
            ],
            "load_balancer": {
                "enabled": self.load_balancer.enabled,
                "servers": load_servers,
            },
        }

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        if datapath.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            in_port = msg.match['in_port']
        else:
            in_port = msg.in_port

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        # DEBUG LOGGING FOR PACKET_IN
        self.logger.debug("packet_in: dpid=%s in_port=%s src=%s dst=%s", datapath.id, in_port, eth.src if eth else "none", eth.dst if eth else "none")

        if eth.ethertype == 0x88cc: return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        self.switch_packet_count[dpid] += 1
        self.total_packet_count += 1
        self.total_byte_count += len(msg.data or b"")

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt and self.load_balancer.enabled:
            if arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip == self.LOAD_BALANCER_VIP:
                # Reply to ARP requests for the VIP with a dummy MAC
                vip_mac = "aa:bb:cc:dd:ee:ff"
                reply = packet.Packet()
                reply.add_protocol(ethernet.ethernet(
                    ethertype=eth.ethertype,
                    dst=eth.src,
                    src=vip_mac))
                reply.add_protocol(arp.arp(
                    opcode=arp.ARP_REPLY,
                    src_mac=vip_mac,
                    src_ip=self.LOAD_BALANCER_VIP,
                    dst_mac=arp_pkt.src_mac,
                    dst_ip=arp_pkt.src_ip))
                reply.serialize()

                actions = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=ofproto.OFPP_CONTROLLER,
                    actions=actions,
                    data=reply.data)
                datapath.send_msg(out)
                return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if ip_pkt:
            self.host_index[src] = {
                "ip": ip_pkt.src,
                "switch": dpid,
                "in_port": in_port,
                "last_seen": time.time(),
            }

            if self.ddos_detector.detect_ddos(ip_pkt.src):
                if ip_pkt.src not in self.blocked_ips:
                    self.sec_logger.log_event(
                        "ddos",
                        "DDoS traffic threshold exceeded",
                        severity="warning",
                        details={"ip": ip_pkt.src, "threshold_pps": self.DDOS_THRESHOLD_PPS},
                    )
                    self.ddos_detector.mitigate_ddos(
                        datapath,
                        ip_pkt.src,
                        add_flow_func=self.add_flow,
                        logger=self.sec_logger,
                        hard_timeout=30,
                    )
                    self.blocked_ips.add(ip_pkt.src)
                    eventlet.spawn_after(30, self.blocked_ips.discard, ip_pkt.src)
                return

            if self.load_balancer.enabled and ip_pkt.dst == self.LOAD_BALANCER_VIP:
                server = self.load_balancer.choose_server()
                if server:
                    server_mac = None
                    for mac, info in self.host_index.items():
                        if info.get("ip") == server["ip"]:
                            server_mac = mac
                            break
                            
                    if server_mac:
                        server["mac"] = server_mac
                        
                    self.load_balancer.install_flow_rule(
                        datapath,
                        add_flow_func=self.add_flow,
                        client_ip=ip_pkt.src,
                        vip_ip=self.LOAD_BALANCER_VIP,
                        server=server,
                        logger=self.sec_logger,
                    )

                    out_port = int(server.get("port", ofproto.OFPP_FLOOD))
                    if datapath.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION and server.get("ip"):
                        actions = [
                            parser.OFPActionSetField(ipv4_dst=server["ip"]),
                        ]
                        if server_mac:
                            actions.append(parser.OFPActionSetField(eth_dst=server_mac))
                        actions.append(parser.OFPActionOutput(out_port))
                    else:
                        actions = [parser.OFPActionOutput(out_port)]

                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=msg.buffer_id,
                        in_port=in_port,
                        actions=actions,
                        data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None,
                    )
                    datapath.send_msg(out)
                    return

        if ip_pkt and tcp_pkt:
            if tcp_pkt.dst_port == self.SSH_PORT and (tcp_pkt.bits & 0x02):
                src_ip = ip_pkt.src
                curr = time.time()
                suspicious = self.bruteforce_detector.detect_bruteforce(src_ip, now=curr)
                attempt_count = self.bruteforce_detector.get_attempt_count(src_ip)

                self.sec_logger.log_event(
                    "ssh_attempt",
                    "Observed SSH connection attempt",
                    details={
                        "ip": src_ip,
                        "count": attempt_count,
                        "threshold": self.THRESHOLD,
                    },
                )

                if suspicious:
                    if src_ip not in self.blocked_ips:
                        self.sec_logger.log_event(
                            "bruteforce",
                            "Brute-force pattern detected",
                            severity="warning",
                            details={"ip": src_ip, "window": self.WINDOW},
                        )
                        self.bruteforce_detector.block_ip(
                            datapath,
                            src_ip,
                            add_flow_func=self.add_flow,
                            logger=self.sec_logger,
                        )
                        self.blocked_ips.add(src_ip)
                        eventlet.spawn_after(self.BLOCK_TIME, self.blocked_ips.discard, src_ip)
                    return

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        # Do not install flow rules so all packets go to the controller
        # if out_port != ofproto.OFPP_FLOOD:
        #     if datapath.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
        #         match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
        #     else:
        #         match = parser.OFPMatch(in_port=in_port, dl_dst=dst)
        #     self.add_flow(datapath, 1, match, actions)

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
        datapath.send_msg(out)

    def _start_custom_rest_server(self, port=8080):
        try:
            server = eventlet.listen(('0.0.0.0', port))
            self.sec_logger.log_event("api", "Starting eventlet raw API server on port "+str(port))
            while True:
                client, addr = server.accept()
                eventlet.spawn(self._handle_api_request, client)
        except Exception as e:
            self.sec_logger.log_event("api_error", str(e), severity="error")

    def _handle_api_request(self, client):
        try:
            data = client.recv(4096).decode('utf-8', errors='ignore')
            if not data:
                return
            lines = data.split('\r\n')
            if not lines:
                return
            req_line = lines[0].split(' ')
            if len(req_line) < 2:
                return
            method, path = req_line[0], req_line[1]

            response = {}
            status = "200 OK"

            if path == '/api/status' and method == 'GET':
                response = self.get_status()
            elif path == '/api/attacks' and method == 'GET':
                response = [self._format_event(e) for e in self.sec_logger.get_recent_attacks(limit=100)]
            elif path == '/api/block_ip' and method == 'POST':
                try:
                    body_start = data.find('\r\n\r\n') + 4
                    if body_start >= 4:
                        body_text = data[body_start:]
                        import json
                        body = json.loads(body_text) if body_text.strip() else {}
                        ip = body.get('ip')
                        duration = int(body.get('duration', 120))
                        if ip:
                            self.block_ip(ip, duration=duration, reason="api")
                            response = {"status": "ok", "blocked_ip": ip}
                        else:
                            status = "400 Bad Request"
                            response = {"error": "missing ip field"}
                    else:
                        status = "400 Bad Request"
                        response = {"error": "missing body"}
                except Exception as e:
                    status = "400 Bad Request"
                    response = {"error": str(e)}
            elif path == '/api/load_balancer/enable' and method == 'POST':
                self.enable_load_balancer()
                response = {"status": "enabled"}
            elif path == '/api/load_balancer/disable' and method == 'POST':
                self.disable_load_balancer()
                response = {"status": "disabled"}
            elif path == '/health' and method == 'GET':
                response = {"status": "ok"}
            else:
                status = "404 Not Found"
                response = {"error": "not found"}

            import json
            res_body = json.dumps(response)
            res_headers = (
                "HTTP/1.1 " + status + "\r\n"
                "Content-Type: application/json\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "Content-Length: " + str(len(res_body)) + "\r\n"
                "Connection: close\r\n\r\n"
            )
            client.sendall((res_headers + res_body).encode('utf-8'))
        except Exception as e:
            pass
        finally:
            client.close()
