from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView
from PyQt6.QtCore import Qt
from helpers import ThreatLevel

class TrafficTable(QTableWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setColumnCount(7)
        self.setHorizontalHeaderLabels(["Время", "Src IP", "Dst IP", "Src Port", "Dst Port", "Протокол", "Размер (B)"])
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.setSortingEnabled(True)
        self.setAlternatingRowColors(True)

    def add_packet(self, pkt: dict):
        row = self.rowCount()
        self.insertRow(row)
        self.setItem(row, 0, QTableWidgetItem(str(pkt.get("timestamp", ""))))
        self.setItem(row, 1, QTableWidgetItem(pkt.get("src_ip", "")))
        self.setItem(row, 2, QTableWidgetItem(pkt.get("dst_ip", "")))
        self.setItem(row, 3, QTableWidgetItem(str(pkt.get("src_port", 0))))
        self.setItem(row, 4, QTableWidgetItem(str(pkt.get("dst_port", 0))))
        self.setItem(row, 5, QTableWidgetItem(pkt.get("protocol", "")))
        self.setItem(row, 6, QTableWidgetItem(str(pkt.get("size", 0))))
        self.scrollToBottom()

    def clear(self):
        self.setRowCount(0)