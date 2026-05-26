from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QHBoxLayout
from PyQt6.QtGui import QColor
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt

class StatsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.figure = Figure(figsize=(5, 3), dpi=100)
        self.canvas = FigureCanvas(self.figure)
        self.ax = self.figure.add_subplot(111)
        self.stats_data = {"protocols": {}}

        self.export_btn = QPushButton("Экспорт в CSV")
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("📊 Статистика и графики"))
        layout.addWidget(self.canvas)
        layout.addWidget(self.export_btn)

    def update_chart(self, stats: dict):
        self.stats_data = stats
        protocols = stats.get("protocols", {})
        if not protocols:
            protocols = {"Нет данных": 1}
        self.ax.clear()
        labels = list(protocols.keys())
        sizes = list(protocols.values())
        self.ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140, colors=['#FF9999','#66B2FF','#99FF99','#FFCC99','#FFD699'])
        self.ax.set_title("Распределение протоколов")
        self.canvas.draw()

    def clear_chart(self):
        self.ax.clear()
        self.ax.set_title("Ожидание данных...")
        self.canvas.draw()