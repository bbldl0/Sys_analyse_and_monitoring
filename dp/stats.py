import logging
from collections import defaultdict

class NetworkStats:
    def __init__(self):
        self.logger = logging.getLogger("NetworkMonitor.Stats")
        self.packets_count = 0
        self.bytes_received = 0
        self.bytes_sent = 0
        self.threats_count = 0
        self.active_ips = set()
        self.protocol_dist = defaultdict(int)
        self.hourly_traffic = defaultdict(float)

    def add_packet(self, data: dict):
        self.packets_count += 1
        self.bytes_received += data.get("size", 0)
        self.active_ips.add(data.get("src_ip"))
        self.active_ips.add(data.get("dst_ip"))
        self.protocol_dist[data.get("protocol", "OTHER")] += 1

    def add_threat(self):
        self.threats_count += 1

    def get_snapshot(self) -> dict:
        return {
            "packets": self.packets_count,
            "bytes": self.bytes_received,
            "threats": self.threats_count,
            "active_ips": len(self.active_ips),
            "protocols": dict(self.protocol_dist),
            "speed_mbps": (self.bytes_received * 8) / (1024 * 1024)
        }