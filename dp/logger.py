import logging
import os
from datetime import datetime
from PyQt6.QtCore import QObject, pyqtSignal

class LogEmitter(QObject):
    log_signal = pyqtSignal(str, str, str)  # timestamp, level, message

class QtHandler(logging.Handler):
    def __init__(self, emitter):
        super().__init__()
        self.emitter = emitter

    def emit(self, record):
        msg = self.format(record)
        self.emitter.log_signal.emit(
            datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S"),
            record.levelname,
            msg
        )

def setup_logger(config):
    log_level = getattr(logging, config.get("analysis", {}).get("log_level", "INFO").upper(), logging.INFO)
    log_file = config.get("analysis", {}).get("log_file", "network_monitor.log")

    logger = logging.getLogger("NetworkMonitor")
    logger.setLevel(log_level)

    # Консольный вывод
    console = logging.StreamHandler()
    console.setLevel(log_level)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    console.setFormatter(formatter)
    logger.addHandler(console)

    # Файловый вывод
    try:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        logging.warning(f"Не удалось создать файл логов: {e}")

    # PyQt-эмиттер для GUI
    emitter = LogEmitter()
    qt_handler = QtHandler(emitter)
    qt_handler.setFormatter(formatter)
    logger.addHandler(qt_handler)

    return logger, emitter