import threading

from ryu.ofproto import ofproto_v1_3


class RoundRobinLoadBalancer:
    """Simple round-robin server selector with optional flow installation."""

    def __init__(self, servers=None):
        self._servers = servers or []
        self._index = 0
        self.enabled = False
        self._lock = threading.Lock()

    def set_servers(self, servers):
        with self._lock:
            self._servers = servers
            self._index = 0

    def add_server(self, server):
        with self._lock:
            self._servers.append(server)

    def remove_server(self, server_ip):
        with self._lock:
            self._servers = [s for s in self._servers if s.get("ip") != server_ip]
            self._index = 0 if self._index >= len(self._servers) else self._index

    def enable(self):
        self.enabled = True

    def disable(self):
        self.enabled = False

    def get_servers(self):
        with self._lock:
            return list(self._servers)

    def choose_server(self):
        with self._lock:
            if not self._servers:
                return None
            server = self._servers[self._index % len(self._servers)]
            self._index = (self._index + 1) % len(self._servers)
            return server

    def install_flow_rule(
        self,
        datapath,
        add_flow_func,
        client_ip,
        vip_ip,
        server,
        logger=None,
    ):
        """Installs a forwarding flow for VIP traffic to a chosen backend server."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        out_port = int(server.get("port", ofproto.OFPP_FLOOD))

        # OpenFlow 1.3 supports rewriting destination IP before forwarding.
        if ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION and server.get("ip"):
            actions = [
                parser.OFPActionSetField(ipv4_dst=server["ip"]),
                parser.OFPActionOutput(out_port),
            ]
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=client_ip, ipv4_dst=vip_ip)
        else:
            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch()

        add_flow_func(datapath, 20, match, actions, hard_timeout=30)
        if logger:
            logger.log_event(
                "load_balance",
                "Distributed flow to backend server",
                severity="info",
                details={
                    "client_ip": client_ip,
                    "vip_ip": vip_ip,
                    "server": server,
                },
            )
