network_monitor/
├── main.py
├── config.json
├── requirements.txt
├── README.md
├── schema.sql
├── core/
│   ├── __init__.py
│   ├── sniffer.py
│   ├── analyzer.py
│   ├── load_tester.py
│   └── stats.py
├── db/
│   ├── __init__.py
│   ├── connection.py
│   └── repository.py
├── gui/
│   ├── __init__.py
│   ├── main_window.py
│   └── widgets/
│       ├── __init__.py
│       ├── traffic_table.py
│       ├── connections_list.py
│       ├── event_log.py
│       ├── stats_panel.py
│       └── settings_panel.py
└── utils/
    ├── __init__.py
    ├── logger.py
    └── helpers.py