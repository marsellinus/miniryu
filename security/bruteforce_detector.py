import socket
import struct
import time

from ryu.ofproto import ofproto_v1_0, ofproto_v1_3


class BruteForceDetector:
    """Detects repeated connection attempts in a short window."""

    def __init__(self, threshold=5, window_seconds=30, block_time=60):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.block_time = block_time
        self._attempts = {}

    @staticmethod
    def _ip_to_int(ip_str):
        return struct.unpack("!I", socket.inet_aton(ip_str))[0]

    def detect_bruteforce(self, src_ip, now=None):
        now = now if now is not None else time.time()
        self._attempts.setdefault(src_ip, [])
        self._attempts[src_ip] = [
            t for t in self._attempts[src_ip] if now - t <= self.window_seconds
        ]
        self._attempts[src_ip].append(now)
        return len(self._attempts[src_ip]) >= self.threshold

    def block_ip(self, datapath, src_ip, add_flow_func, logger=None):
        parser = datapath.ofproto_parser
        version = datapath.ofproto.OFP_VERSION

        if version == ofproto_v1_3.OFP_VERSION:
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        else:
            src_ip_int = self._ip_to_int(src_ip)
            match = parser.OFPMatch(dl_type=0x0800, nw_src=src_ip_int)

        add_flow_func(datapath, 100, match, [], hard_timeout=self.block_time)
        if logger:
            logger.log_event(
                "blocked_ip",
                "Blocked IP due to brute-force threshold",
                severity="warning",
                details={"ip": src_ip, "duration": self.block_time},
            )

    def reset_counter(self, src_ip=None):
        if src_ip is None:
            self._attempts.clear()
            return
        self._attempts.pop(src_ip, None)

    def get_attempt_count(self, src_ip):
        return len(self._attempts.get(src_ip, []))
