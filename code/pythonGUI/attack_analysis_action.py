from PyQt5.QtGui import QFont

from PyQt5.QtWidgets import *
import sys

from pythonGUI.capture_analysis import attack_detection as attacking
from pythonGUI.capture_analysis import plotting
from pythonGUI import attack_analysis_window

class AttackAnalysisWindow(attack_analysis_window.Ui_MainWindow, QMainWindow):
    def __init__(self, data, main_window, flagged_IPs):
        super(AttackAnalysisWindow, self).__init__()
        self.setupUi(self)
        self.data_use = data

        self.parent = main_window
        self.flagged_IPs = flagged_IPs
        self.attack_detect = attacking.AttackDetection(self.data_use, self.flagged_IPs)

        # triggers methods if buttons are clicked
        self.actionTCPSYN.triggered.connect(self.tcp_syn_flood_detect)
        self.actionDOS.triggered.connect(self.dos_detect)
        self.actionTCPscan.triggered.connect(self.tcp_scanning_detect)
        self.actionARPPoi.triggered.connect(self.arp_poison_detect)
        self.actionICMP.triggered.connect(self.icmp_flood_detect)
        self.actionHTTP_Flood.triggered.connect(self.http_flood_detect)
        self.actionDNS.triggered.connect(self.dns_flood_detect)
        self.actionrunAll.triggered.connect(self.run_all_detect)
        self.actionFlagged.triggered.connect(self.display_flagged_addr)


        self.imported_IPs = []

    # when subwindow is closed save suspicious addresses to mainwindow and then close
    def closeEvent(self, event):
        for address in self.attack_detect.suspicious_addresses:
            if address not in self.parent.flaggedIPs:
                self.parent.flaggedIPs.append(address)
        event.accept()


    def tcp_syn_flood_detect(self):
        # gets graph canvas from calling attack detection method
        canvas = self.attack_detect.tcp_syn_flood_detect()
        suspicious = self.attack_detect.tcp_suspicious_addresses
        attacked = self.attack_detect.attacked_addresses

        # creates main widget and layout
        central = QWidget()
        layout = QVBoxLayout()

        suspicious_text = ""
        attacked_text = ""

        # if no graph is created then no packets were present
        if canvas is None:
            suspicious_text = "No TCP SYN or SYN-ACK packets present, no suspicious addresses detected"
        else:
            if not suspicious:
                suspicious_text = "No suspicious addresses detected"
            elif suspicious:
                suspicious_text = "Suspicious addresses: "
                suspicious_addresses = ', '.join(suspicious)
                suspicious_text = suspicious_text + suspicious_addresses

            if not attacked:
                attacked_text = "No attacked addresses detected"
            elif attacked:
                attacked_text = "Suspected Attacked addresses: "
                attacked_addresses = ', '.join(attacked)
                attacked_text = attacked_text + attacked_addresses

        suspicious_label = QLabel(suspicious_text + "\n" + attacked_text)
        suspicious_label.setFont(QFont('Arial', 15))

        explanation_text = "The suspicious addresses were marked because these addresses send a greater amount of " \
                           "SYN requests than it does receive SYN-ACK responses back, suggesting it is overloading a" \
                           "system. \nThe attacked addresses were marked because these addresses receive a greater " \
                           "amount of SYN requests than it sends SYN-ACK responses back, which is indicative that " \
                           "these addresses are being overwhelmed by SYN requests and cant response fast enough. "

        explain_label = QLabel("\nExplanation:")
        explain_label.setFont(QFont('Arial', 12))

        explanation_label = QLabel(explanation_text)
        explanation_label.setFont(QFont('Arial', 10))
        explanation_label.setWordWrap(True)


        layout.addWidget(canvas)
        layout.addWidget(suspicious_label)

        if canvas is not None:
            layout.addWidget(explain_label)
            layout.addWidget(explanation_label)
            layout.addStretch()

        self.setCentralWidget(central)
        central.setLayout(layout)


    def tcp_scanning_detect(self):
        threshold = self.threshold_input.text()
        if threshold == '':
            threshold = 100
        else:
            threshold = int(threshold)

        canvas = self.attack_detect.tcp_connect_scanning_detect(threshold)
        suspicious = self.attack_detect.tcp_scanning_suspicious

        central = QWidget()
        layout = QVBoxLayout()

        suspicious_text = ""
        if canvas is None:
            suspicious_text = "No TCP (SYN) packets present, no suspicious addresses detected"
        else:
            if not suspicious:
                suspicious_text = "No suspicious addresses detected"
            elif suspicious:
                suspicious_text = "Suspicious addresses: "
                suspicious_addresses = ', '.join(suspicious)
                suspicious_text = suspicious_text + suspicious_addresses



        explain_label = QLabel("\nExplanation:")
        explain_label.setFont(QFont('Arial', 12))

        explanation_text = "Addresses are marked as suspicious if the address sends SYN flags without receiving " \
                           "SYN-ACK packets and if the same address sends more SYN packets than the threshold within " \
                           "the time interval. "

        explanation_label = QLabel(explanation_text)
        explanation_label.setFont(QFont('Arial', 10))
        explanation_label.setWordWrap(True)

        suspicious_label = QLabel(suspicious_text)
        suspicious_label.setFont(QFont('Arial', 15))
        suspicious_label.setWordWrap(True)

        layout.addWidget(canvas)
        layout.addWidget(suspicious_label)

        if canvas is not None:
            layout.addWidget(explain_label)
            layout.addWidget(explanation_label)
            layout.addStretch()

        self.setCentralWidget(central)
        central.setLayout(layout)

    def dos_detect(self):
        threshold = self.threshold_input.text()
        if threshold == '':
            threshold = 200
        else:
            threshold = int(threshold)

        canvas = self.attack_detect.threshold_dos_detect(threshold)
        suspicious = self.attack_detect.dos_suspicious_addresses

        central = QWidget()
        layout = QVBoxLayout()

        suspicious_text = ""
        explanation_label = QLabel("")

        if canvas is None:
            suspicious_text = "No packets present"
        else:
            if not suspicious:
                suspicious_text = "No suspicious addresses detected"
            elif suspicious:
                suspicious_text = "Suspicious addresses: "
                suspicious_addresses = ', '.join(suspicious)
                suspicious_text = suspicious_text + suspicious_addresses
                explanation_label = QLabel(
                    "These addresses are sending a greater amount of traffic then the threshold and therefore are marked as suspicious.")

        suspicious_label = QLabel(suspicious_text)
        suspicious_label.setFont(QFont('Arial', 15))
        suspicious_label.setWordWrap(True)

        explanation_label.setFont(QFont('Arial', 10))
        explanation_label.setWordWrap(True)

        layout.addWidget(canvas)
        layout.addWidget(suspicious_label)
        layout.addWidget(explanation_label)
        layout.addStretch()

        self.setCentralWidget(central)
        central.setLayout(layout)

    def arp_poison_detect(self):
        canvas = self.attack_detect.arp_poison_detect()
        suspicious = self.attack_detect.arp_suspicious_addresses

        central = QWidget()
        layout = QVBoxLayout()

        suspicious_text = ""
        if canvas is None:
            suspicious_text = "No ARP packets present, no suspicious addresses detected"

        else:
            if not suspicious:
                suspicious_text = "No suspicious addresses detected"
            elif suspicious:
                suspicious_text = "Suspicious addresses: "
                suspicious_addresses = ', '.join(suspicious)
                suspicious_text = suspicious_text + suspicious_addresses

        suspicious_label = QLabel(suspicious_text)
        suspicious_label.setFont(QFont('Arial', 15))
        suspicious_label.setWordWrap(True)

        explain_label = QLabel("\nExplanation:")
        explain_label.setFont(QFont('Arial', 12))

        explanation_text = "These addresses were marked because the MAC addresses they originated from are associated " \
                           "with more than one IP address, which is erroneous and indicative of ARP Poisoning."

        explanation_label = QLabel(explanation_text)
        explanation_label.setFont(QFont('Arial', 10))
        explanation_label.setWordWrap(True)

        layout.addWidget(canvas)
        layout.addWidget(suspicious_label)

        if canvas is not None:
            layout.addWidget(explain_label)
            layout.addWidget(explanation_label)
            layout.addStretch()

        self.setCentralWidget(central)
        central.setLayout(layout)

    def icmp_flood_detect(self):
        threshold = self.threshold_input.text()
        if threshold == '':
            threshold = 100
        else:
            threshold = int(threshold)
        canvas = self.attack_detect.icmp_flood_detect(threshold)
        suspicious = self.attack_detect.icmp_suspicious

        central = QWidget()
        layout = QVBoxLayout()

        suspicious_text = ""

        if canvas is None:
            suspicious_text = "No ICMP packets present, no suspicious addresses detected"
        else:
            if not suspicious:
                suspicious_text = "No suspicious addresses detected"
            elif suspicious:
                suspicious_text = "Suspicious addresses: "
                suspicious_addresses = ', '.join(suspicious)
                suspicious_text = suspicious_text + suspicious_addresses

        suspicious_label = QLabel(suspicious_text)
        suspicious_label.setFont(QFont('Arial', 15))
        suspicious_label.setWordWrap(True)

        explain_label = QLabel("\nExplanation:")
        explain_label.setFont(QFont('Arial', 12))

        explanation_text = "These addresses were marked because the ICMP Echo packets sent from these addresses are " \
                           "over too high a frequency. "

        explanation_label = QLabel(explanation_text)
        explanation_label.setFont(QFont('Arial', 10))
        explanation_label.setWordWrap(True)

        layout.addWidget(canvas)
        layout.addWidget(suspicious_label)

        if canvas is not None:
            layout.addWidget(explain_label)
            layout.addWidget(explanation_label)
            layout.addStretch()

        self.setCentralWidget(central)
        central.setLayout(layout)

    def http_flood_detect(self):
        threshold = self.threshold_input.text()
        if threshold == '':
            threshold = 5
        else:
            threshold = int(threshold)
        canvas = self.attack_detect.http_attack(threshold)
        suspicious = self.attack_detect.http_suspicious

        central = QWidget()
        layout = QVBoxLayout()

        suspicious_text = ""

        if canvas is None:
            suspicious_text = "No HTTP packets present or no TCP handshake was established, no suspicious addresses detected"
        else:
            if not suspicious:
                suspicious_text = "No suspicious addresses detected"
            elif suspicious:
                suspicious_text = "Suspicious addresses: "
                suspicious_addresses = ', '.join(suspicious)
                suspicious_text = suspicious_text + suspicious_addresses

        suspicious_label = QLabel(suspicious_text)
        suspicious_label.setFont(QFont('Arial', 15))
        suspicious_label.setWordWrap(True)

        explain_label = QLabel("\nExplanation:")
        explain_label.setFont(QFont('Arial', 12))

        explanation_text = "These addresses were marked because the HTTP Request packets sent from these addresses " \
                           "after a tcp connection are established are " \
                           "over too high a frequency. "

        explanation_label = QLabel(explanation_text)
        explanation_label.setFont(QFont('Arial', 10))
        explanation_label.setWordWrap(True)

        layout.addWidget(canvas)
        layout.addWidget(suspicious_label)

        if canvas is not None:
            layout.addWidget(explain_label)
            layout.addWidget(explanation_label)
            layout.addStretch()

        self.setCentralWidget(central)
        central.setLayout(layout)

    def dns_flood_detect(self):
        threshold = self.threshold_input.text()
        if threshold == '':
            threshold = 20
        else:
            threshold = int(threshold)
        canvases = self.attack_detect.dns_request_response_detect(threshold)

        central = QWidget()
        layout = QVBoxLayout()

        request_graph = canvases[0]
        response_graph = canvases[1]

        if request_graph is None and response_graph is None:
            suspicious_text = "No DNS packets present, no suspicious addresses detected"
        else:
            request_suspicious = self.attack_detect.dns_request_suspicious
            response_suspicious = self.attack_detect.dns_response_suspicious

            request_suspicious_text = ""

            if request_graph is None:
                request_suspicious_text = "No DNS Request packets present, no suspicious addresses detected"
            else:
                if not request_suspicious:
                    request_suspicious_text = "No DNS Request suspicious addresses detected"
                elif request_suspicious:
                    request_suspicious_text = "DNS Request suspicious addresses: "
                    suspicious_addresses = ', '.join(request_suspicious)
                    request_suspicious_text = request_suspicious_text + suspicious_addresses

            response_suspicious_text = ""

            if response_graph is None:
                response_suspicious_text = "No DNS Response packets present, no suspicious addresses detected"
            else:
                if not response_suspicious:
                    request_suspicious_text = "No DNS Response suspicious addresses detected"
                elif response_suspicious:
                    response_suspicious_text = "DNS Response suspicious addresses: "
                    suspicious_addresses = ', '.join(response_suspicious)
                    response_suspicious_text = response_suspicious_text + suspicious_addresses

            suspicious_text = request_suspicious_text + "\n" + response_suspicious_text

            layout.addWidget(request_graph)
            layout.addWidget(response_graph)

        suspicious_label = QLabel(suspicious_text)
        suspicious_label.setFont(QFont('Arial', 15))
        suspicious_label.setWordWrap(True)

        explain_label = QLabel("\nExplanation:")
        explain_label.setFont(QFont('Arial', 12))

        explanation_text = "These addresses were marked because the DNS packets sent from these addresses are " \
                           "over too high a frequency. "

        explanation_label = QLabel(explanation_text)
        explanation_label.setFont(QFont('Arial', 10))
        explanation_label.setWordWrap(True)

        layout.addWidget(suspicious_label)

        if request_graph is not None or response_graph is not None:
            layout.addWidget(explain_label)
            layout.addWidget(explanation_label)
            layout.addStretch()

        self.setCentralWidget(central)
        central.setLayout(layout)

    def run_all_detect(self):
        threshold = self.threshold_input.text()
        if threshold == '':
            threshold = None
        else:
            threshold = int(threshold)

        self.attack_detect.run_all_detection(threshold)

        central = QWidget()
        layout = QVBoxLayout()


        dns_suspicious = self.attack_detect.dns_request_suspicious + self.attack_detect.dns_response_suspicious

        # Dictionary of attack detection methods in order to enumerate through them
        attack_list = {"DOS": self.attack_detect.dos_suspicious_addresses,
                       "TCP Scanning": self.attack_detect.tcp_scanning_suspicious,
                       "TCP": self.attack_detect.tcp_suspicious_addresses,
                       "ICMP": self.attack_detect.icmp_suspicious,
                       "HTTP": self.attack_detect.http_suspicious,
                       "ARP": self.attack_detect.arp_suspicious_addresses,
                       "DNS": dns_suspicious}

        # creates gui labels for each attack
        for attack in attack_list:
            suspicious_text = ""
            if not attack_list[attack]:
                suspicious_text = attack + ": no suspicious addresses detected"
            elif attack:
                suspicious_text = attack + " suspicious addresses: "
                suspicious_addresses = ', '.join(attack_list[attack])
                suspicious_text = suspicious_text + suspicious_addresses

            suspicious_label = QLabel(suspicious_text)
            suspicious_label.setFont(QFont('Arial', 15))
            suspicious_label.setWordWrap(True)

            layout.addWidget(suspicious_label)

        layout.addStretch()
        self.setCentralWidget(central)
        central.setLayout(layout)

    def display_flagged_addr(self):
        central = QWidget()
        layout = QVBoxLayout()

        suspicious = self.attack_detect.suspicious_addresses
        if not suspicious:
            suspicious_text = "No suspicious addresses detected"
        elif suspicious:
            suspicious_text = "Suspicious addresses: "
            suspicious_addresses = ', '.join(suspicious)
            suspicious_text = suspicious_text + suspicious_addresses

        suspicious_label = QLabel(suspicious_text)
        suspicious_label.setFont(QFont('Arial', 15))
        suspicious_label.setWordWrap(True)

        layout.addWidget(suspicious_label)

        save_button = QPushButton(central)
        save_button.setText("Save flagged IP addresses")
        save_button.clicked.connect(self.saveIPList)

        import_button = QPushButton(central)
        import_button.setText("Import flagged IP addresses")
        import_button.clicked.connect(self.importIPList)

        layout.addWidget(save_button)
        layout.addWidget(import_button)
        self.setCentralWidget(central)
        central.setLayout(layout)

    def saveIPList(self):
        file_name = QFileDialog.getSaveFileName(self, 'Save File')
        addresses = self.attack_detect.suspicious_addresses

        if file_name[0] != "":
            file_name_txt = file_name[0] + ".txt"
            file = open(file_name[0], 'w')
            for ip in addresses:
                file.write(ip + '\n')
            file.close()

    def importIPList(self):
        imported_ips = []
        file_name = QFileDialog.getOpenFileName(self, 'Open file', "", 'All files (*);; txt (*.txt)')

        file = open(file_name[0], 'r')

        lines = file.read().splitlines()


        for line in lines:
            imported_ips.append(str(line))
        file.close()

        self.attack_detect.update_flagged_ips(imported_ips)
        self.display_flagged_addr()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = AttackAnalysisWindow()
    window.show()
    app.exec_()
