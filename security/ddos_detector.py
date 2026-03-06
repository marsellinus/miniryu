import socket
import struct
import time
from collections import defaultdict, deque

from ryu.ofproto import ofproto_v1_0, ofproto_v1_3


class DDoSDetector:
    """Tracks packet rates and flags sources above a packets/sec threshold."""

    def __init__(self, packets_per_second_threshold=1000, window_seconds=1.0):
        self.threshold = packets_per_second_threshold
        self.window_seconds = window_seconds
        self._traffic = defaultdict(deque)

    @staticmethod
    def _ip_to_int(ip_str):
        return struct.unpack("!I", socket.inet_aton(ip_str))[0]

    def monitor_traffic(self, src_ip, now=None):
        now = now if now is not None else time.time()
        queue = self._traffic[src_ip]
        queue.append(now)
        while queue and (now - queue[0]) > self.window_seconds:
            queue.popleft()
        return len(queue) / max(self.window_seconds, 0.001)

    def detect_ddos(self, src_ip, now=None):
        current_rate = self.monitor_traffic(src_ip, now=now)
        return current_rate >= self.threshold

    def mitigate_ddos(self, datapath, src_ip, add_flow_func, logger=None, hard_timeout=30):
        parser = datapath.ofproto_parser
        version = datapath.ofproto.OFP_VERSION

        if version == ofproto_v1_3.OFP_VERSION:
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        else:
            src_ip_int = self._ip_to_int(src_ip)
            match = parser.OFPMatch(dl_type=0x0800, nw_src=src_ip_int)

        add_flow_func(datapath, 110, match, [], hard_timeout=hard_timeout)
        if logger:
            logger.log_event(
                "ddos",
                "Applied temporary DDoS mitigation drop rule",
                severity="warning",
                details={"ip": src_ip, "duration": hard_timeout},
            )

    def get_rates(self):
        snapshot = {}
        now = time.time()
        for src_ip, queue in self._traffic.items():
            while queue and (now - queue[0]) > self.window_seconds:
                queue.popleft()
            snapshot[src_ip] = len(queue) / max(self.window_seconds, 0.001)
        return snapshot
