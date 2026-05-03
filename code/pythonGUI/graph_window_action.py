from PyQt5.QtGui import QFont

from PyQt5.QtWidgets import *
import sys

from pythonGUI.capture_analysis import plotting as plotting
from pythonGUI import graph_window


class GraphWindow(graph_window.Ui_MainWindow, QMainWindow):
    def __init__(self, data):
        super(GraphWindow, self).__init__()
        self.setupUi(self)
        self.data_use = data

        self.plotter = plotting.Plotting(self.data_use)

        self.actionProtocol.triggered.connect(self.protocol_analysis)
        self.actionIPv4Network.triggered.connect(self.ipv4_network_analysis)
        self.actionIPv6Network.triggered.connect(self.ipv6_network_analysis)
        self.actionMACNetwork.triggered.connect(self.mac_network_analysis)
        self.actionSource.triggered.connect(self.source_analysis)
        self.actionDest.triggered.connect(self.dest_analysis)

    def protocol_analysis(self):
        canvas = self.plotter.plot_protocol()

        central_widget = self.centralWidget()
        if central_widget is not None:
            central_widget.deleteLater()
        self.setCentralWidget(None)

        self.setCentralWidget(canvas)

    def ipv4_network_analysis(self):
        canvas = self.plotter.ipv4_network_graph()

        central = QWidget()
        layout = QVBoxLayout()

        label = QLabel("IPv4 Network Graph")
        label.setFont(QFont('Arial', 30))
        layout.addWidget(label, stretch=1)
        layout.addWidget(canvas, stretch=9)
        self.setCentralWidget(central)
        central.setLayout(layout)

    def ipv6_network_analysis(self):
        canvas = self.plotter.ipv6_network_graph()

        central = QWidget()
        layout = QVBoxLayout()

        label = QLabel("IPv6 Network Graph")
        label.setFont(QFont('Arial', 30))
        layout.addWidget(label, stretch=1)
        layout.addWidget(canvas, stretch=9)
        self.setCentralWidget(central)
        central.setLayout(layout)


    def mac_network_analysis(self):
        canvas = self.plotter.mac_network_graph()
        central = QWidget()
        layout = QVBoxLayout()

        label = QLabel("MAC Network Graph")
        label.setFont(QFont('Arial', 30))
        layout.addWidget(label, stretch=1)
        layout.addWidget(canvas, stretch=9)
        self.setCentralWidget(central)
        central.setLayout(layout)

    def source_analysis(self):
        canvas = self.plotter.plot_source()
        central_widget = self.centralWidget()

        if central_widget is not None:
            central_widget.deleteLater()
        self.setCentralWidget(None)

        self.setCentralWidget(canvas)

    def dest_analysis(self):
        canvas = self.plotter.plot_dest()
        central_widget = self.centralWidget()

        if central_widget is not None:
            central_widget.deleteLater()
        self.setCentralWidget(None)

        self.setCentralWidget(canvas)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    myWindow = GraphWindow()
    myWindow.show()
    app.exec_()
