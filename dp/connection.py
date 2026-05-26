import pyodbc
import logging
from typing import Optional

class DatabaseManager:
    def __init__(self, config: dict):
        self.config = config
        self.connection: Optional[pyodbc.Connection] = None
        self.logger = logging.getLogger("NetworkMonitor.DB")

    def connect(self) -> bool:
        db_cfg = self.config["database"]
        if db_cfg.get("trusted_connection"):
            conn_str = (
                f"DRIVER={db_cfg['driver']};"
                f"SERVER={db_cfg['server']};"
                f"DATABASE={db_cfg['database']};"
                f"Trusted_Connection=yes;"
                f"Timeout={db_cfg.get('timeout', 10)};"
            )
        else:
            conn_str = (
                f"DRIVER={db_cfg['driver']};"
                f"SERVER={db_cfg['server']};"
                f"DATABASE={db_cfg['database']};"
                f"UID={db_cfg.get('user', '')};"
                f"PWD={db_cfg.get('password', '')};"
                f"Timeout={db_cfg.get('timeout', 10)};"
            )
        try:
            self.connection = pyodbc.connect(conn_str, autocommit=False)
            self.logger.info("Подключение к MS SQL Server установлено.")
            self._ensure_tables()
            return True
        except Exception as e:
            self.logger.error(f"Ошибка подключения к БД: {e}")
            self.connection = None
            return False

    def _ensure_tables(self):
        script = """
        IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[suspicious_ports]') AND type in (N'U'))
        BEGIN
            CREATE TABLE [dbo].[suspicious_ports] (
                [id] INT IDENTITY(1,1) PRIMARY KEY,
                [port] INT NOT NULL,
                [threat_level] NVARCHAR(50),
                [detected_at] DATETIME DEFAULT GETDATE()
            );
        END

        IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[traffic_logs]') AND type in (N'U'))
        BEGIN
            CREATE TABLE [dbo].[traffic_logs] (
                [id] INT IDENTITY(1,1) PRIMARY KEY,
                [src_ip] NVARCHAR(45),
                [dst_ip] NVARCHAR(45),
                [src_port] INT,
                [dst_port] INT,
                [protocol] NVARCHAR(10),
                [size_bytes] INT,
                [timestamp] DATETIME DEFAULT GETDATE()
            );
        END

        IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[events]') AND type in (N'U'))
        BEGIN
            CREATE TABLE [dbo].[events] (
                [id] INT IDENTITY(1,1) PRIMARY KEY,
                [event_type] NVARCHAR(100),
                [threat_level] NVARCHAR(50),
                [src_ip] NVARCHAR(45),
                [dst_ip] NVARCHAR(45),
                [port] INT,
                [description] NVARCHAR(1000),
                [detected_at] DATETIME DEFAULT GETDATE()
            );
        END

        IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[statistics]') AND type in (N'U'))
        BEGIN
            CREATE TABLE [dbo].[statistics] (
                [id] INT IDENTITY(1,1) PRIMARY KEY,
                [metric_name] NVARCHAR(100),
                [metric_value] FLOAT,
                [recorded_at] DATETIME DEFAULT GETDATE()
            );
        END
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute(script)
            self.connection.commit()
            self.logger.info("Таблицы БД проверены/созданы успешно.")
        except Exception as e:
            self.logger.error(f"Ошибка создания таблиц: {e}")

    def execute_query(self, query: str, params: tuple = ()) -> bool:
        if not self.connection:
            return False
        try:
            cursor = self.connection.cursor()
            cursor.execute(query, params)
            self.connection.commit()
            return True
        except Exception as e:
            self.logger.error(f"Ошибка SQL-запроса: {e}")
            return False

    def close(self):
        if self.connection:
            try:
                self.connection.close()
            except Exception:
                pass
            self.logger.info("Соединение с БД закрыто.")