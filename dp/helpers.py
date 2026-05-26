import csv
import ipaddress
from enum import Enum
from typing import List, Dict, Any

class ThreatLevel(Enum):
    LOW = "Низкий"
    MEDIUM = "Средний"
    HIGH = "Высокий"
    CRITICAL = "Критический"

    def get_color(self) -> str:
        return {
            ThreatLevel.LOW: "#4CAF50",
            ThreatLevel.MEDIUM: "#FFC107",
            ThreatLevel.HIGH: "#FF5722",
            ThreatLevel.CRITICAL: "#F44336"
        }[self]

def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def calculate_bandwidth(packets: List[Dict[str, Any]], window_sec: float = 1.0) -> float:
    """Расчет пропускной способности в байтах/сек"""
    if not packets:
        return 0.0
    total_bytes = sum(p.get("size", 0) for p in packets)
    return total_bytes / max(window_sec, 0.001)

def export_to_csv(filepath: str, data: List[List[str]], headers: List[str]):
    try:
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(data)
    except Exception as e:
        raise RuntimeError(f"Ошибка экспорта CSV: {e}")