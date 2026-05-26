import socket
import threading
import logging
import time
from PyQt6.QtCore import QThread, pyqtSignal

class LoadTester(QThread):
    progress_signal = pyqtSignal(int, int, str)
    finished_signal = pyqtSignal(bool, str)
    error_signal = pyqtSignal(str)

    def __init__(self, config: dict):
        super().__init__()
        self.logger = logging.getLogger("NetworkMonitor.LoadTester")
        self.config = config["load_test"]
        self._stop = threading.Event()

    def run(self):
        """Основной метод потока (вызывается при start())"""
        try:
            self._stop.clear()
            
            total_threads = self.config.get("threads", 10)
            packets = self.config.get("packets_per_thread", 1000)
            target = self.config.get("target_ip", "127.0.0.1")
            port = self.config.get("target_port", 80)
            proto = self.config.get("protocol", "TCP")

            self.logger.info(f"Тест запущен: {proto} -> {target}:{port}")
            self.progress_signal.emit(0, 0, "Запуск...")

            workers = []
            for i in range(total_threads):
                if self._stop.is_set(): 
                    break
                t = threading.Thread(
                    target=self._worker, 
                    args=(i, target, port, proto, packets), 
                    daemon=True
                )
                workers.append(t)
                t.start()

            for t in workers:
                t.join()

            if not self._stop.is_set():
                self.finished_signal.emit(True, "Тест завершен успешно")
                
        except Exception as e:
            self.error_signal.emit(str(e))
            self.logger.error(e)

    def start_test(self):
        """Публичный метод для запуска теста (вызывает run через QThread)"""
        self.start()

    def stop_test(self):
        self.logger.info("Остановка теста...")
        self._stop.set()

    def _worker(self, tid, target, port, proto, count):
        success = 0
        fail = 0
        for i in range(count):
            if self._stop.is_set(): 
                break
            try:
                if proto.upper() == "TCP":
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1)
                    s.connect((target, port))
                    s.close()
                else:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.sendto(b"TEST", (target, port))
                    s.close()
                success += 1
            except:
                fail += 1
            
            if i % 50 == 0:
                self.progress_signal.emit(tid, count, f"Поток {tid}: {success}/{fail}")
            time.sleep(0.005)