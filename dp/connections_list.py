from PyQt6.QtWidgets import QListWidget, QListWidgetItem
from PyQt6.QtCore import Qt
import psutil

class ConnectionsList(QListWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

    def refresh(self):
        self.clear()
        try:
            conns = psutil.net_connections(kind='inet')
            for c in conns:
                status = c.status if c.status != 'NONE' else ''
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                self.addItem(f"{c.pid or 'N/A'} | {laddr} -> {raddr} | {status}")
        except Exception as e:
            self.addItem(f"Ошибка получения соединений: {e}")