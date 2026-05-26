from PyQt6.QtWidgets import (QMainWindow, QTabWidget, QVBoxLayout, QWidget, 
                             QHBoxLayout, QMessageBox, QPushButton, QGroupBox, QLabel, QStatusBar)
from PyQt6.QtCore import QTimer, QThread
import logging
from datetime import datetime
from traffic_table import TrafficTable
from connections_list import ConnectionsList
from event_log import EventLog
from stats_panel import StatsPanel
from settings_panel import SettingsPanel
from sniffer import PacketSniffer
from analyzer import TrafficAnalyzer
from load_tester import LoadTester
from stats import NetworkStats
from connection import DatabaseManager
from repository import DBRepository

class MainWindow(QMainWindow):
    def __init__(self, config: dict, db: DatabaseManager, repo: DBRepository, logger: logging.Logger):
        super().__init__()
        self.config = config
        self.db = db
        self.repo = repo
        self.logger = logger
        self.stats = NetworkStats()
        self.analyzer = TrafficAnalyzer(config)

        self.setWindowTitle("Система мониторинга и анализа сетевого трафика")
        self.resize(1100, 750)

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self._setup_ui()

        # СНАЧАЛА создаем объекты
        self.sniffer = PacketSniffer(self.analyzer, config)
        self.load_tester = LoadTester(config)
        self.load_thread = QThread()
        self.load_tester.moveToThread(self.load_thread)

        # ПОТОМ подключаем сигналы
        self.sniffer.packet_received.connect(self.on_packet)
        self.sniffer.threat_detected.connect(self.on_threats)
        self.sniffer.error_occurred.connect(self.handle_error)
        
        self.load_tester.progress_signal.connect(self.update_load_progress)
        self.load_tester.finished_signal.connect(self.on_load_finished)
        self.load_tester.error_signal.connect(self.handle_error)
        
        self.load_thread.started.connect(self.load_tester.start_test)

        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.update_connections)
        self.refresh_timer.start(config.get("ui", {}).get("auto_refresh_ms", 1000))

        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("Готово к запуску")

    def _setup_ui(self):
        self.tab_main = QWidget()
        layout = QVBoxLayout(self.tab_main)

        # Контролы
        ctrl_layout = QHBoxLayout()
        self.btn_start = QPushButton("▶ Запуск анализа")
        self.btn_stop = QPushButton("⏹ Остановка")
        self.btn_load = QPushButton("🚀 Нагрузочный тест")
        self.btn_clear = QPushButton("🗑 Очистить")
        self.btn_export = QPushButton("💾 Экспорт CSV")
        ctrl_layout.addWidget(self.btn_start)
        ctrl_layout.addWidget(self.btn_stop)
        ctrl_layout.addWidget(self.btn_load)
        ctrl_layout.addWidget(self.btn_clear)
        ctrl_layout.addWidget(self.btn_export)
        layout.addLayout(ctrl_layout)

        # Сетка
        grid_layout = QHBoxLayout()
        self.table = TrafficTable()
        grid_layout.addWidget(self.table, 2)

        right_layout = QVBoxLayout()
        self.conn_list = ConnectionsList()
        right_layout.addWidget(QLabel("Активные подключения:"))
        right_layout.addWidget(self.conn_list, 1)

        self.event_log = EventLog()
        right_layout.addWidget(QLabel("Журнал событий:"))
        right_layout.addWidget(self.event_log, 1)

        grid_layout.addLayout(right_layout, 1)
        layout.addLayout(grid_layout, 2)

        # Статистика
        self.stats_panel = StatsPanel()
        layout.addWidget(self.stats_panel, 1)

        self.tabs.addTab(self.tab_main, "📡 Мониторинг")

        # Вкладка настроек
        self.settings = SettingsPanel("config.json")
        self.settings.settings_saved.connect(self.reload_config)
        self.tabs.addTab(self.settings, "⚙️ Настройки")

        # Вкладка БД
        db_tab = QWidget()
        db_layout = QVBoxLayout(db_tab)
        self.db_status = QLabel("Статус БД: Проверка...")
        self.db_btn = QPushButton("Переподключить БД")
        self.db_btn.clicked.connect(self.reconnect_db)
        db_layout.addWidget(self.db_status)
        db_layout.addWidget(self.db_btn)
        self.tabs.addTab(db_tab, "💾 База данных")

        self.btn_start.clicked.connect(self.start_monitoring)
        self.btn_stop.clicked.connect(self.stop_monitoring)
        self.btn_load.clicked.connect(self.run_load_test)
        self.btn_clear.clicked.connect(self.clear_all)
        self.btn_export.clicked.connect(self.export_csv)

        self.update_db_status()

    def start_monitoring(self):
        self.logger.info("Запуск мониторинга...")
        if not self.sniffer.isRunning():
            self.sniffer.start()
            self.statusBar.showMessage("Сниффер запущен")

    def stop_monitoring(self):
        self.logger.info("Остановка мониторинга...")
        self.sniffer.stop()
        self.sniffer.wait(2000)
        self.statusBar.showMessage("Сниффер остановлен")

    def run_load_test(self):
        if self.load_thread.isRunning():
            self.load_tester.stop_test()
            self.load_thread.quit()
            self.load_thread.wait()
            self.statusBar.showMessage("Нагрузочный тест остановлен")
            return

        self.load_thread.start()
        self.statusBar.showMessage("Нагрузочный тест запущен...")

    def on_packet(self, pkt: dict):
        self.table.add_packet(pkt)
        self.stats.add_packet(pkt)

        self.repo.insert_traffic_log(
            pkt["src_ip"], pkt["dst_ip"], pkt["src_port"], 
            pkt["dst_port"], pkt["protocol"], pkt["size"]
        )
        self.update_stats_ui()

    def on_threats(self, threats: list):
        for t in threats:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.event_log.add_event(ts, t["level"].name, t["type"], t["src_ip"], t["desc"])
            self.stats.add_threat()
            self.repo.insert_event(
                t["type"], t["level"].name, t["src_ip"], t["dst_ip"], 
                t["port"], t["desc"]
            )
            self.logger.warning(f"Угроза: {t['type']} | {t['desc']}")
        self.update_stats_ui()

    def update_load_progress(self, tid, total, msg):
        self.statusBar.showMessage(f"Нагрузочный тест: Поток {tid} -> {msg}")

    def on_load_finished(self, success: bool, msg: str):
        self.statusBar.showMessage(msg)
        if success:
            self.logger.info("Нагрузочный тест завершен.")

    def update_connections(self):
        self.conn_list.refresh()

    def update_stats_ui(self):
        snapshot = self.stats.get_snapshot()
        self.stats_panel.update_chart(snapshot)
        # Сохраняем метрики в БД
        self.repo.insert_statistic("packets_count", snapshot["packets"])
        self.repo.insert_statistic("threats_count", snapshot["threats"])

    def update_db_status(self):
        status = "✅ Подключено" if self.db.connection else "❌ Отключено"
        self.db_status.setText(f"Статус БД: {status}")

    def handle_error(self, message: str):
        """Отображение критических ошибок"""
        self.statusBar.showMessage(f"Ошибка: {message}")

    def reconnect_db(self):
        self.db.close()
        self.db.connect()
        self.update_db_status()

    def reload_config(self, new_config: dict):
        self.config = new_config

    def clear_all(self):
        self.table.clear()
        self.event_log.clear()
        self.stats = NetworkStats()
        self.stats_panel.clear_chart()
        self.analyzer.reset_stats()
        self.logger.info("Интерфейс и статистика очищены.")

    def export_csv(self):
        import os
        filepath = "traffic_export.csv"
        headers = ["Время", "Src IP", "Dst IP", "Src Port", "Dst Port", "Протокол", "Размер"]
        data = []
        for r in range(self.table.rowCount()):
            row_data = [self.table.item(r, c).text() for c in range(self.table.columnCount())]
            data.append(row_data)
        try:
            from helpers import export_to_csv
            export_to_csv(filepath, data, headers)
            self.logger.info(f"Статистика экспортирована в {os.path.abspath(filepath)}")
        except Exception as e:
            self.logger.error(f"Ошибка экспорта: {e}")
    def handle_error(self, message: str):
        """Обработка ошибок от сниффера и тестера"""
        self.logger.error(f"Ошибка: {message}")
        self.statusBar.showMessage(f"Ошибка: {message}")
        QMessageBox.warning(self, "Ошибка", message)