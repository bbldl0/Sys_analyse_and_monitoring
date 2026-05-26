import logging
import threading
from PyQt6.QtCore import QThread, pyqtSignal

# Импорт scapy отложенный, чтобы не блокировать интерфейс при старте
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from analyzer import TrafficAnalyzer

class PacketSniffer(QThread):
    packet_received = pyqtSignal(dict)
    threat_detected = pyqtSignal(list)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, analyzer: TrafficAnalyzer, config: dict):
        super().__init__()
        self.logger = logging.getLogger("NetworkMonitor.Sniffer")
        self.analyzer = analyzer
        self.config = config["sniffer"]
        self._running = False
        self._stop_event = threading.Event()

    def run(self):
        if not SCAPY_AVAILABLE:
            self.error_occurred.emit("Библиотека Scapy не установлена!")
            return

        self._running = True
        self.logger.info("Сниффер запущен.")
        
        iface = self.config.get("interface") or None
        if not iface:
            iface = None # None значит "все интерфейсы"

        try:
            # Запускаем sniff внутри потока QThread
            sniff(
                iface=iface,
                prn=self._process_packet,
                store=0,
                stop_filter=lambda x: not self._running
            )
        except PermissionError:
            self.error_occurred.emit("Нет прав администратора для захвата пакетов!")
        except Exception as e:
            self.error_occurred.emit(f"Ошибка сниффера: {str(e)}")
        finally:
            self._running = False
            self.logger.info("Сниффер остановлен.")

    def stop(self):
        self.logger.info("Получена команда остановки...")
        self._running = False

    def _process_packet(self, packet):
        try:
            if not packet.haslayer(IP):
                return

            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            size = len(packet)
            
            protocol = "OTHER"
            src_port = dst_port = 0

            if packet.haslayer(TCP):
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif packet.haslayer(ICMP):
                protocol = "ICMP"

            pkt_data = {
                "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": src_port, "dst_port": dst_port,
                "protocol": protocol, "size": size, "timestamp": packet.time
            }
            
            # Отправляем данные в GUI
            self.packet_received.emit(pkt_data)

            # Анализ угроз
            threats = self.analyzer.analyze_packet(
                src_ip, dst_ip, src_port, dst_port, protocol, size
            )
            if threats:
                self.threat_detected.emit(threats)

        except Exception as e:
            # Ловим ошибки обработки пакетов, чтобы не крашить всё приложение
            self.logger.error(f"Ошибка в пакете: {e}")