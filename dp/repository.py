import logging
from datetime import datetime
from connection import DatabaseManager

class DBRepository:
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.logger = logging.getLogger("NetworkMonitor.Repo")

    def insert_traffic_log(self, src_ip, dst_ip, src_port, dst_port, protocol, size):
        query = """
        INSERT INTO traffic_logs (src_ip, dst_ip, src_port, dst_port, protocol, size_bytes)
        VALUES (?, ?, ?, ?, ?, ?)
        """
        return self.db.execute_query(query, (src_ip, dst_ip, src_port, dst_port, protocol, size))

    def insert_event(self, event_type, threat_level, src_ip, dst_ip, port, description):
        query = """
        INSERT INTO events (event_type, threat_level, src_ip, dst_ip, port, description)
        VALUES (?, ?, ?, ?, ?, ?)
        """
        return self.db.execute_query(query, (event_type, threat_level, src_ip, dst_ip, port, description))

    def insert_suspicious_port(self, port, threat_level):
        query = "INSERT INTO suspicious_ports (port, threat_level) VALUES (?, ?)"
        return self.db.execute_query(query, (port, threat_level))

    def insert_statistic(self, metric_name: str, metric_value: float):
        query = "INSERT INTO statistics (metric_name, metric_value) VALUES (?, ?)"
        return self.db.execute_query(query, (metric_name, metric_value))