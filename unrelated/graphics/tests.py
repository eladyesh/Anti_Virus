import matplotlib

matplotlib.use("Qt5Agg")
from PyQt5 import QtWidgets
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import matplotlib.pyplot as plt
import numpy as np
import sys
import colorcet as cc


class LogDisplay(QtWidgets.QMainWindow):
    def __init__(self, logs):
        super().__init__()

        self.logs = logs

        self.central_widget = QtWidgets.QWidget()
        self.setCentralWidget(self.central_widget)

        self.layout = QtWidgets.QVBoxLayout(self.central_widget)

        self.figure = plt.figure()
        self.canvas = FigureCanvas(self.figure)
        self.layout.addWidget(self.canvas)

        self.display_logs()

    def display_logs(self):
        params = ['Time Difference', 'CPU Usage', 'Number of Calls']
        values = []
        functions = []
        grouped_logs = {}
        for log in self.logs:
            if log['function'] in grouped_logs:
                grouped_logs[log['function']]['values'] = [sum(x) for x in
                                                           zip(grouped_logs[log['function']]['values'], log['values'])]
                grouped_logs[log['function']]['count'] += 1
            else:
                grouped_logs[log['function']] = {
                    'function': log['function'],
                    'values': log['values'],
                    'count': 1
                }
        for key, value in grouped_logs.items():
            functions.append(value['function'])
            values.append([x / value['count'] for x in value['values']])

        self.figure.clear()
        legend_patches = []
        colors = [cc.rainbow[i*15] for i in range(17)]

        for i in range(len(params)):
            ax = self.figure.add_subplot(1, 3, i + 1)
            bar_width = 0.05
            for j, value in enumerate(values):
                x = np.arange(1)
                bar = ax.bar(x + j * bar_width, value[i], bar_width, color=colors[j])
                if i == 0:
                    legend_patches.append(bar[0])
            ax.set_xticks(x)
            ax.set_xticklabels([params[i]])

        self.figure.legend(handles=legend_patches, labels=functions, fontsize=10, ncol=1, loc='upper left',
                           bbox_to_anchor=(0, 1), frameon=False)
        self.canvas.draw()

app = QtWidgets.QApplication(sys.argv)
logs = [{'function': 'CreateFileA', 'values': [1.7458603, 0.0, 1.0]}, {'function': 'VirtualAlloc', 'values': [1.750075, 0.0, 1.0]}, {'function': 'CreateFileA', 'values': [1.7532286, 0.0, 2.0]}, {'function': 'VirtualAlloc', 'values': [1.7583793, 99.8856, 2.0]}, {'function': 'RegOpenKeyExA', 'values': [1.7619944, 99.8856, 1.0]}, {'function': 'RegSetValueExA', 'values': [1.7648602, 99.8856, 1.0]}, {'function': 'RegCreateKeyExA', 'values': [1.7676261, 99.8856, 1.0]}, {'function': 'RegOpenKeyExA', 'values': [1.7711509, 0.113408, 2.0]}, {'function': 'RegGetValueA', 'values': [1.7738437, 0.113408, 1.0]}, {'function': 'socket', 'values': [1.778857, 0.113408, 1.0]}, {'function': 'connect', 'values': [1.7820397, 0.113408, 1.0]}, {'function': 'socket', 'values': [1.871519, 0.113408, 2.0]}, {'function': 'connect', 'values': [1.8851605, 0.113408, 2.0]}, {'function': 'socket', 'values': [2.29359786, 0.113408, 3.0]}, {'function': 'connect', 'values': [2.29501144, 0.113408, 3.0]}, {'function': 'socket', 'values': [4.40606236, 0.113408, 4.0]}, {'function': 'connect', 'values': [4.40743876, 0.113408, 4.0]}, {'function': 'send', 'values': [4.41492391, 0.113408, 1.0]}, {'function': 'recv', 'values': [4.42745373, 12.5053, 1.0]}, {'function': 'DeleteFileA', 'values': [4.42810529, 12.5053, 1.0]}, {'function': 'WriteFileEx', 'values': [4.42943189, 12.5053, 1.0]}, {'function': 'WriteFile', 'values': [4.43020745, 99.535, 1.0]}, {'function': 'OpenProcess', 'values': [4.4325011, 0.350021, 1.0]}, {'function': 'VirtualAllocEx', 'values': [4.43320334, 0.350021, 1.0]}, {'function': 'CreateRemoteThread', 'values': [4.43405798, 99.8945, 1.0]}, {'function': 'CloseHandle', 'values': [4.43447616, 99.8945, 1.0]}]
window = LogDisplay(logs)
window.show()
sys.exit(app.exec_())
