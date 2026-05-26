import logging
from collections import defaultdict
from helpers import ThreatLevel

class TrafficAnalyzer:
    def __init__(self, config: dict):
        self.config = config["analysis"]
        self.logger = logging.getLogger("NetworkMonitor.Analyzer")
        self.connection_tracker = defaultdict(int)
        self.port_scan_tracker = defaultdict(set)
        self.request_rate = defaultdict(int)
        self.suspicious_ports = set(self.config.get("suspicious_ports", []))
        self.port_threshold = self.config.get("port_scan_threshold", 15)
        self.conn_threshold = self.config.get("connection_threshold", 50)

    def analyze_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str, size: int):
        events = []

        self.connection_tracker[f"{src_ip}->{dst_ip}"] += 1
        self.port_scan_tracker[src_ip].add(dst_port)
        self.request_rate[src_ip] += 1

        # Проверка на сканирование портов
        if len(self.port_scan_tracker[src_ip]) >= self.port_threshold:
            events.append({
                "type": "PORT_SCAN",
                "level": ThreatLevel.HIGH,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "port": dst_port,
                "desc": f"Обнаружено сканирование портов с {src_ip} ({len(self.port_scan_tracker[src_ip])} портов)"
            })

        # Проверка на большое количество соединений
        conn_key = f"{src_ip}->{dst_ip}"
        if self.connection_tracker[conn_key] > self.conn_threshold:
            events.append({
                "type": "HIGH_CONNECTIONS",
                "level": ThreatLevel.MEDIUM,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "port": dst_port,
                "desc": f"Аномальное количество соединений между {src_ip} и {dst_ip}"
            })

        # Подозрительные порты
        if dst_port in self.suspicious_ports:
            events.append({
                "type": "SUSPICIOUS_PORT",
                "level": ThreatLevel.HIGH,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "port": dst_port,
                "desc": f"Трафик через подозрительный порт {dst_port}"
            })

        if events:
            return events
        return []

    def reset_stats(self):
        self.connection_tracker.clear()
        self.port_scan_tracker.clear()
        self.request_rate.clear()