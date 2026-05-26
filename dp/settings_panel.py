from PyQt6.QtWidgets import (QWidget, QFormLayout, QLineEdit, QCheckBox, 
                             QPushButton, QSpinBox, QLabel, QMessageBox, QVBoxLayout, QGroupBox)
from PyQt6.QtCore import pyqtSignal
import json
import os

class SettingsPanel(QWidget):
    settings_saved = pyqtSignal(dict)

    def __init__(self, config_path: str, parent=None):
        super().__init__(parent)
        self.config_path = config_path
        self.config = self._load_config()
        self._build_ui()

    def _load_config(self) -> dict:
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"database": {}, "analysis": {}, "sniffer": {}}

    def _build_ui(self):
        main_layout = QVBoxLayout()
        
        # Группа БД
        db_group = QGroupBox("База данных")
        db_layout = QFormLayout()
        self.db_server = QLineEdit(self.config.get("database", {}).get("server", "HOME-PC"))
        self.db_name = QLineEdit(self.config.get("database", {}).get("database", "TrafficMonitor"))
        db_layout.addRow("Сервер:", self.db_server)
        db_layout.addRow("База:", self.db_name)
        db_group.setLayout(db_layout)
        
        # Группа анализа
        analysis_group = QGroupBox("Пороги анализа")
        a_layout = QFormLayout()
        self.port_thresh = QSpinBox()
        self.port_thresh.setRange(1, 1000)
        self.port_thresh.setValue(self.config.get("analysis", {}).get("port_scan_threshold", 15))
        self.conn_thresh = QSpinBox()
        self.conn_thresh.setRange(1, 10000)
        self.conn_thresh.setValue(self.config.get("analysis", {}).get("connection_threshold", 50))
        a_layout.addRow("Сканирование портов:", self.port_thresh)
        a_layout.addRow("Макс. соединений:", self.conn_thresh)
        analysis_group.setLayout(a_layout)
        
        self.save_btn = QPushButton("💾 Сохранить настройки")
        self.save_btn.clicked.connect(self.save_settings)
        

        main_layout.addWidget(db_group)
        main_layout.addWidget(analysis_group)
        main_layout.addWidget(self.save_btn)
        main_layout.addStretch()
        
        self.setLayout(main_layout)

    def save_settings(self):
        self.config["database"]["server"] = self.db_server.text()
        self.config["database"]["database"] = self.db_name.text()
        self.config["analysis"]["port_scan_threshold"] = self.port_thresh.value()
        self.config["analysis"]["connection_threshold"] = self.conn_thresh.value()
        try:
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=2)
            QMessageBox.information(self, "Успех", "Конфигурация сохранена.")
            self.settings_saved.emit(self.config)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))