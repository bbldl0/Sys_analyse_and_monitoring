import sys
import os
import json
import logging
import ctypes
import traceback
from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt
from logger import setup_logger
from connection import DatabaseManager
from repository import DBRepository
from main_window import MainWindow

def load_config(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Ошибка загрузки config.json: {e}")
        return {}

def handle_exception(exc_type, exc_value, exc_traceback):
    """Глобальный перехватчик ошибок, чтобы программа не вылетала молча"""
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    error_string = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    
    print("КРИТИЧЕСКАЯ ОШИБКА ПРОГРАММЫ:")
    print(error_string)
    
    try:
        with open("crash_report.log", "a", encoding="utf-8") as f:
            f.write(f"\n--- ERROR REPORT ---\n{error_string}\n")
    except:
        pass

    try:
        QMessageBox.critical(None, "Критическая ошибка", 
                             f"Программа столкнулась с ошибкой:\n\n{str(exc_value)}\n\n"
                             f"Подробности в файле crash_report.log")
    except:
        pass

def main():
    sys.excepthook = handle_exception

    try:
        app = QApplication(sys.argv)
        app.setFont(QFont("Segoe UI", 10))
        
        config_path = os.path.join(os.path.dirname(__file__), "config.json")
        config = load_config(config_path)
        
        if not config:
            QMessageBox.critical(None, "Ошибка", "Файл config.json не найден или поврежден.")
            sys.exit(1)

        logger, emitter = setup_logger(config)
        
        # Инициализация БД
        db = DatabaseManager(config)
        db_connected = db.connect()
        repo = DBRepository(db) if db_connected else None

        if not db_connected:
            logger.warning("БД не подключена.")
            QMessageBox.warning(None, "База данных", 
                                "Не удалось подключиться к MS SQL Server.\n"
                                "Проверьте config.json (server: HOME-PC).\n"
                                "Программа запустится в демо-режиме (без сохранения в БД).")

        window = MainWindow(config, db, repo, logger)
        window.show()
        
        
        sys.exit(app.exec())

    except Exception as e:
        print(f"Ошибка запуска: {e}")

if __name__ == "__main__":
    # Проверка прав админа для Windows
    if sys.platform == "win32":
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("⚠️ ВНИМАНИЕ: Запустите программу от имени Администратора!")
                print("️ Без этого захват пакетов (Sniffer) может не работать.")
        except:
            pass
    
    main()