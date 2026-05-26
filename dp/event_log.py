from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem, QLineEdit, QHBoxLayout, QVBoxLayout, QPushButton, QWidget
from PyQt6.QtCore import Qt
from helpers import ThreatLevel

class EventLog(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Время", "Уровень", "Тип", "IP", "Описание"])
        self.table.setSortingEnabled(True)

        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Поиск по журналу...")
        self.search_box.textChanged.connect(self.filter_events)

        self.clear_btn = QPushButton("Очистить журнал")

        layout = QVBoxLayout(self)
        search_layout = QHBoxLayout()
        search_layout.addWidget(self.search_box)
        search_layout.addWidget(self.clear_btn)
        layout.addLayout(search_layout)
        layout.addWidget(self.table)

        self._all_events = []

        self.clear_btn.clicked.connect(self.clear)

    def add_event(self, timestamp: str, level: str, event_type: str, ip: str, desc: str):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(timestamp))
        level_item = QTableWidgetItem(level)
        if level in ThreatLevel.__members__:
            level_item.setBackground(ThreatLevel[level].get_color())
        self.table.setItem(row, 1, level_item)
        self.table.setItem(row, 2, QTableWidgetItem(event_type))
        self.table.setItem(row, 3, QTableWidgetItem(ip))
        self.table.setItem(row, 4, QTableWidgetItem(desc))
        self._all_events.append([timestamp, level, event_type, ip, desc])
        self.table.scrollToBottom()

    def filter_events(self):
        text = self.search_box.text().lower()
        self.table.setRowCount(0)
        for ev in self._all_events:
            if text in " ".join(ev).lower():
                self.add_event(*ev)

    def clear(self):
        self.table.setRowCount(0)
        self._all_events.clear()