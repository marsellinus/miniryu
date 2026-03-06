import json
import time
from collections import defaultdict

from webob import Response

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import tcp
from ryu.ofproto import ofproto_v1_0, ofproto_v1_3
from ryu.app.wsgi import ControllerBase, WSGIApplication, route

from network.load_balancer import RoundRobinLoadBalancer
from security.bruteforce_detector import BruteForceDetector
from security.ddos_detector import DDoSDetector
from utils.logger import security_logger


REST_INSTANCE_NAME = "sdn_rest_api"
REST_BASE_PATH = "/api"

class AntiBruteForceSwitch(app_manager.RyuApp):
    _CONTEXTS = {"wsgi": WSGIApplication}
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
        self.logger = security_logger

        wsgi = kwargs["wsgi"]
        wsgi.register(SDNControllerRestAPI, {REST_INSTANCE_NAME: self})

        self.logger.log_event(
            "controller",
            "Anti-Brute-Force Shield Active with REST API",
            details={"versions": ["OpenFlow1.3", "OpenFlow1.0"]},
        )

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath

        if datapath.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, 0, match, actions)
        else:
            match = parser.OFPMatch()
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
        self.logger.log_event(
            "blocked_ip",
            "Manually blocked source IP",
            severity="warning",
            details={"ip": src_ip, "duration": duration, "reason": reason},
        )

    def enable_load_balancer(self):
        self.load_balancer.enable()
        self.logger.log_event("load_balance", "Load balancer enabled")

    def disable_load_balancer(self):
        self.load_balancer.disable()
        self.logger.log_event("load_balance", "Load balancer disabled")

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
                for event in self.logger.get_recent_attacks(limit=100)
            ],
            "alerts": [
                self._format_event(event)
                for event in self.logger.get_recent_events(limit=100)
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
        if eth.ethertype == 0x88cc: return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        self.switch_packet_count[dpid] += 1
        self.total_packet_count += 1
        self.total_byte_count += len(msg.data or b"")

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
                    self.logger.log_event(
                        "ddos",
                        "DDoS traffic threshold exceeded",
                        severity="warning",
                        details={"ip": ip_pkt.src, "threshold_pps": self.DDOS_THRESHOLD_PPS},
                    )
                    self.ddos_detector.mitigate_ddos(
                        datapath,
                        ip_pkt.src,
                        add_flow_func=self.add_flow,
                        logger=self.logger,
                        hard_timeout=30,
                    )
                    self.blocked_ips.add(ip_pkt.src)
                return

            if self.load_balancer.enabled and ip_pkt.dst == self.LOAD_BALANCER_VIP:
                server = self.load_balancer.choose_server()
                if server:
                    self.load_balancer.install_flow_rule(
                        datapath,
                        add_flow_func=self.add_flow,
                        client_ip=ip_pkt.src,
                        vip_ip=self.LOAD_BALANCER_VIP,
                        server=server,
                        logger=self.logger,
                    )

                    out_port = int(server.get("port", ofproto.OFPP_FLOOD))
                    if datapath.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION and server.get("ip"):
                        actions = [
                            parser.OFPActionSetField(ipv4_dst=server["ip"]),
                            parser.OFPActionOutput(out_port),
                        ]
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

                self.logger.log_event(
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
                        self.logger.log_event(
                            "bruteforce",
                            "Brute-force pattern detected",
                            severity="warning",
                            details={"ip": src_ip, "window": self.WINDOW},
                        )
                        self.bruteforce_detector.block_ip(
                            datapath,
                            src_ip,
                            add_flow_func=self.add_flow,
                            logger=self.logger,
                        )
                        self.blocked_ips.add(src_ip)
                    return

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            if datapath.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            else:
                match = parser.OFPMatch(in_port=in_port, dl_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
        datapath.send_msg(out)


class SDNControllerRestAPI(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(SDNControllerRestAPI, self).__init__(req, link, data, **config)
        self.sdn_app = data[REST_INSTANCE_NAME]

    @route("network_status", REST_BASE_PATH + "/status", methods=["GET"])
    def network_status(self, req, **kwargs):
        body = json.dumps(self.sdn_app.get_status())
        return Response(content_type="application/json", body=body)

    @route("attacks", REST_BASE_PATH + "/attacks", methods=["GET"])
    def attacks(self, req, **kwargs):
        body = json.dumps(
            [
                self.sdn_app._format_event(event)
                for event in self.sdn_app.logger.get_recent_attacks(limit=100)
            ]
        )
        return Response(content_type="application/json", body=body)

    @route("block_ip", REST_BASE_PATH + "/block_ip", methods=["POST"])
    def block_ip(self, req, **kwargs):
        payload = req.json if req.body else {}
        src_ip = payload.get("ip")
        duration = int(payload.get("duration", 120))
        if not src_ip:
            return Response(status=400, body="missing ip field")

        self.sdn_app.block_ip(src_ip, duration=duration, reason="api")
        return Response(
            content_type="application/json",
            body=json.dumps({"status": "ok", "blocked_ip": src_ip}),
        )

    @route("enable_lb", REST_BASE_PATH + "/load_balancer/enable", methods=["POST"])
    def enable_load_balancer(self, req, **kwargs):
        self.sdn_app.enable_load_balancer()
        return Response(content_type="application/json", body=json.dumps({"status": "enabled"}))

    @route("disable_lb", REST_BASE_PATH + "/load_balancer/disable", methods=["POST"])
    def disable_load_balancer(self, req, **kwargs):
        self.sdn_app.disable_load_balancer()
        return Response(content_type="application/json", body=json.dumps({"status": "disabled"}))