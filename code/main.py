import os.path

from PyQt5.Qt import Qt, QCompleter
from PyQt5.QtCore import QSortFilterProxyModel, QUrl
from PyQt5.QtGui import QColor, QCursor
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog, QTableWidgetItem, QTreeWidgetItem, QMenu, QAction
from PyQt5.QtWidgets import QHeaderView, QAbstractItemView, QComboBox
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from PyQt5.QtGui import QDesktopServices
import webbrowser

from pythonGUI import subWindow, window, graph_window_action, attack_analysis_action

from pythonGUI.capture_analysis import GUI_actions, attack_detection


def hex_packet_data(packet_data):
    result = []
    digits = 4 if isinstance(packet_data, str) else 2

    for i in range(0, len(packet_data), 16):
        data = packet_data[i: i + 16]
        hexa = ' '.join([hex(x)[2:].upper().zfill(digits) for x in data])
        text = ' '.join([chr(x) if 0x20 <= x < 0x7F else '.' for x in data])
        result.append("{0:04X}".format(i) + ' --- ' + hexa.ljust(16 * (digits + 1)) + ' --- ' + "{0}".format(text))

    return ' --- '.join(result)


class Window(window.Ui_MainWindow, QMainWindow):
    def __init__(self):
        super(Window, self).__init__()

        self.data_box_menu = QMenu(self)

        self.detect = None
        self.cwd = None
        self.stopped_capture = False
        self.capture_thread = None
        self.packet_number = 1
        # creates GUI_actions object
        self.GUI_actions = GUI_actions.GUIActions()
        self.setupUi(self)
        self.showMaximized()
        self.flaggedIPs = []
        self.show_in_hex = None
        self.show_in_bin = None

        # set open/save file and quit application function
        self.actionOpen_Multi_Files.triggered.connect(self.open_multiple_file_operation)
        self.actionSave.triggered.connect(self.save_file_operation)
        self.actionSave_As_2.triggered.connect(self.save_as_file_operation)
        self.actionExit.triggered.connect(self.quit_operation)

        # set the capture menu
        self.actionStart.triggered.connect(self.start_capture)
        self.actionStop.triggered.connect(self.stop_capture)
        self.actionPause.triggered.connect(self.pause_capture)

        # set the analysis menu
        self.actionGraph.triggered.connect(self.graph_operation)
        self.actionAttack_Analysis.triggered.connect(self.attack_analysis_operation)

        # set the help menu
        self.actionUse_Guide.triggered.connect(self.use_guide_operation)

        # set display filter
        self.filterBox.setEditable(True)
        self.filterBox.pFilterModel = QSortFilterProxyModel(self)
        self.filterBox.pFilterModel.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self.filterBox.pFilterModel.setSourceModel(self.filterBox.model())

        self.filterBox.completer = QCompleter(self.filterBox.pFilterModel, self)

        self.filterBox.completer.setCompletionMode(QCompleter.UnfilteredPopupCompletion)
        self.filterBox.completer.setCaseSensitivity(Qt.CaseInsensitive)
        self.filterBox.setCompleter(self.filterBox.completer)

        self.filterBox.lineEdit().textEdited.connect(self.filterBox.pFilterModel.setFilterFixedString)
        self.filterBox.completer.activated.connect(self.completer_operate)

        self.filterBot.clicked.connect(self.filter_capture)

        self.filter_list = ["", "ARP", "DNS", "ICMP", "IGMP", "IPv6", "UDP", "TCP"]
        self.filterBox.addItems(self.filter_list)

        # set capture list
        self.captureList.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.captureList.horizontalHeader().setSectionResizeMode(0, QHeaderView.Interactive)
        self.captureList.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.captureList.verticalHeader().setVisible(False)
        self.captureList.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.captureList.cellClicked.connect(self.handle_clicked_row)
        self.captureList.cellClicked.connect(self.get_select_packet)
        self.captureList.cellClicked.connect(self.get_current_list_row)
        self.captureList.cellDoubleClicked.connect(self.handle_double_clicked_row)

        # set sub window
        self.subs = []

        # set graph window
        self.graph_window = None
        self.attack_analysis_window = None

        # set data list
        self.data.horizontalHeader().setVisible(False)
        self.data.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.data.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.data.resizeColumnsToContents()
        self.data.setContextMenuPolicy(Qt.CustomContextMenu)
        self.data.customContextMenuRequested.connect(self.create_rightMenu)
        self.actionTurnHex = QAction('Show hexadecimal data', self)
        self.actionTurnHex.triggered.connect(self.operate_turn_hex)
        self.actionTurnBin = QAction('Show binary data', self)
        self.actionTurnBin.triggered.connect(self.operate_turn_bin)

        # start button pressed
        self.actionStartCapture.triggered.connect(self.start_capture)
        # pause button pressed
        self.actionPauseCapture.triggered.connect(self.pause_capture)
        self.actionPauseCapture.setEnabled(False)
        # stop button pressed
        self.actionStopCaputure.triggered.connect(self.stop_capture)
        self.actionStopCaputure.setEnabled(False)

        # set status bar
        self.statusBar.showMessage('Ready for Capturing')

    def get_current_list_row(self):
        row = self.captureList.currentRow()
        return row

    def get_select_packet(self, row):
        item = self.captureList.item(row, 0)
        selected_packet = self.GUI_actions.sniffer.sniffed_packets[int(item.text()) - 1]
        details = str.splitlines(selected_packet.show(dump=True))
        return selected_packet, details

    # if a row is clicked, then displays the packet's detail at the bottom
    def handle_clicked_row(self, row):
        # gets the first column of the clicked row which is the packet number
        # item = self.captureList.item(row, 0)
        # indexes the packet list to get the correct packet
        # selected_packet = self.GUI_actions.sniffer.sniffed_packets[int(item.text()) - 1]
        selected_packet, details = self.get_select_packet(row)
        self.detail.clear()

        # displays the detailed view of the packet
        # details = str.splitlines(selected_packet.show(dump=True))
        # print(str(selected_packet.show(dump=True)))
        self.display_packet_detail(details)

        self.display_packet_data(selected_packet)

    def display_packet_detail(self, detail):
        root_amount = 0
        root_arr = []
        root_name = []
        root_index_arr = []
        for i in range(len(detail)):
            if detail[i].__contains__('[ '):
                root_amount += 1
                temp = detail[i].strip('|###[ ')
                temp2 = temp.strip(' ]###')
                root_name.append(temp2)
                root_index_arr.append(i)
            else:
                root_index_arr.append(' ')

        # print(root_name)
        # print(root_index_arr)

        for i in range(root_amount):
            root_arr.append(QTreeWidgetItem(self.detail))
            root_arr[i].setText(0, root_name[i])
            # print(root_arr[i].text(0))

        temp_index = 0
        for i in range(len(detail)):
            if i == 0:
                continue
            if i == root_index_arr[i]:
                temp_index += 1
                if temp_index >= root_amount:
                    temp_index = root_amount - 1
                continue
            QTreeWidgetItem(root_arr[temp_index]).setText(0, detail[i])

    # if a row is double-clicked, display the packets detail in new window (subWindow)
    def handle_double_clicked_row(self, row):
        length = len(self.subs)
        self.subs.append(subWindow.SubWindow())
        item = self.captureList.item(row, 0)
        selected_packet = self.GUI_actions.sniffer.sniffed_packets[int(item.text()) - 1]
        details = str.splitlines(selected_packet.show(dump=True))
        # self.subs[length].parse_packet(selected_packet)
        self.subs[length].setWindowTitle("Packet #" + str(row + 1) + "  " + str(selected_packet.sprintf(
            "%Ether.type%"
        )))
        self.subs[length].display_packet_data(selected_packet)
        self.subs[length].display_packet_detail(details)
        self.subs[length].show()


    # opens pcap files and displays its content
    def open_multiple_file_operation(self):
        self.actionStopCaputure.setEnabled(True)
        self.stopped_capture = False
        # gets the filename of the selected files
        file_names, _ = QFileDialog.getOpenFileNames(self, "Open files", "", 'pcap (*.pcap);;All files (*)')
        length = len(file_names)
        temp = 0
        while temp < length:
            if file_names[temp] != '':
                self.GUI_actions.read_pcap(str(file_names[temp]), mainWindow)
            temp += 1

    # saves a pcap file of the captured packets
    def save_file_operation(self):
        file_name = QFileDialog.getSaveFileName(self, 'Save file', "", 'pcap (*.pcap);;All files (*)')
        self.GUI_actions.write_pcap(str(os.path.basename(file_name[0])))

    def save_as_file_operation(self):
        file_name = QFileDialog.getSaveFileName(self, 'Save As', '', 'pcap (*.pcap);;All files (*)')
        self.GUI_actions.write_pcap(str(file_name[0]))

    # closes the GUI window
    def quit_operation(self):
        self.close()

    # pauses the packet capturing, does not remove packets, and doesn't reset packet counter
    def pause_capture(self):
        # disables/enables the buttons
        self.actionStartCapture.setEnabled(True)
        self.actionPauseCapture.setEnabled(False)
        self.actionStopCaputure.setEnabled(True)
        # stops the sniffer
        self.GUI_actions.start_sniffer(False, mainWindow)

    # stops the packet capturing
    def stop_capture(self):
        self.actionStartCapture.setEnabled(True)
        self.actionPauseCapture.setEnabled(False)
        self.actionStopCaputure.setEnabled(False)

        # variable used to remove captured packets from display
        self.stopped_capture = True
        self.captureList.setRowCount(0)
        self.GUI_actions.start_sniffer(False, mainWindow)
        self.packet_number = 1
        # resets captured packets
        self.GUI_actions.sniffer.reset()

        # clear detail and data box
        self.detail.clear()
        self.detail.update()
        self.data.clear()
        self.data.update()

    # method to start sniffer, ran as thread so packets are displayed dynamically
    def start_capture_thread(self):
        self.stopped_capture = False
        self.GUI_actions.sniffer.set_sniff_amount(self.lineEdit.text())
        self.GUI_actions.sniffer.set_filter(self.filterBox.currentText())
        # calls method in GUI_actions to start sniffer, passes window object through
        self.GUI_actions.start_sniffer(True, mainWindow)

    # initialises and starts packet capture thread
    def start_capture(self):
        self.actionStartCapture.setEnabled(False)
        self.actionPauseCapture.setEnabled(True)
        self.actionStopCaputure.setEnabled(True)

        # creates a thread to run simultaneously so the user can still interact with GUI
        self.capture_thread = threading.Thread(target=self.start_capture_thread)
        # starts running the thread
        self.capture_thread.start()

    # open the graph subwindow
    def graph_operation(self):
        data = self.GUI_actions.get_sniffed_packets()
        self.graph_window = graph_window_action.GraphWindow(data)

        self.graph_window.show()

    # open the attack analysis subwindow
    def attack_analysis_operation(self):
        data = self.GUI_actions.get_sniffed_packets()

        self.attack_analysis_window = attack_analysis_action.AttackAnalysisWindow(data, self, self.flaggedIPs)

        self.attack_analysis_window.show()

    def use_guide_operation(self):
        # project_root = os.path.abspath(os.path.dirname(__file__))
        # file_path = f"file://{project_root}/help_resource/index.html"
        # webbrowser.open(file_path)
        webbrowser.open_new_tab('https://ubiquitous-sniffle-y217w7w.pages.github.io/#/')

    # filters captured packets
    def filter_capture(self):
        # gets new list of filtered packets
        filtered_packets = self.GUI_actions.filter_packets(self.filterBox.currentText())
        # removes packets from display
        self.captureList.setRowCount(0)
        self.packet_number = 1
        # displays each packet
        for packet in filtered_packets:
            self.display_packet(packet)

    # in order to use PyQts build in sorting function for tables with integers,
    # need to store integers using this custom item class which allows integer comparison
    class TableItemInt(QTableWidgetItem):
        # less than initializer that allows two items to be compared.
        def __lt__(self, other):
            return int(self.text()) < int(other.text())

    # called whenever a packet is captured by the sniffer, displays this packet in a table
    def display_packet(self, packet):
        # gets current amount of rows
        row_number = self.captureList.rowCount()
        self.captureList.insertRow(row_number)
        # first column for packet number
        packet_number_item = self.TableItemInt(str(self.packet_number))
        self.captureList.setItem(row_number, 0, packet_number_item)
        # 2nd column for timestamp
        self.captureList.setItem(row_number, 1, QTableWidgetItem(
            str(datetime.fromtimestamp(int(packet.time)))))
        # depending on the layers of the packet attributes need to be handled differently
        if packet.haslayer(IP):
            # 3rd column = source address
            self.captureList.setItem(row_number, 2, QTableWidgetItem(packet.getlayer(IP).src))

            # 4th column = destination address
            self.captureList.setItem(row_number, 3, QTableWidgetItem(packet.getlayer(IP).dst))

            # 5th column = protocol obtained from calling function to get protocol name from protocol number
            self.captureList.setItem(row_number, 4,
                                     QTableWidgetItem(
                                         str(self.GUI_actions.get_protocol(packet.getlayer(IP).proto, packet))))

            # 6th column = length of packet
            packet_len_item = self.TableItemInt(str(len(packet)))
            self.captureList.setItem(row_number, 5, packet_len_item)

            # updates capture list for each packet
            self.captureList.update()
            # allows scroll bar to follow most recent captured packet
            self.captureList.verticalScrollBar().setSliderPosition(row_number)

            if self.GUI_actions.get_protocol(packet.getlayer(IP).proto, packet) == "TCP":
                self.set_background(row_number, 193, 210, 240)
            elif self.GUI_actions.get_protocol(packet.getlayer(IP).proto, packet) == "UDP" or "UDP/DNS":
                self.set_background(row_number, 254, 254, 187)
            elif self.GUI_actions.get_protocol(packet.getlayer(IP).proto, packet) == "IGMP":
                self.set_background(row_number, 254, 216, 177)
            elif self.GUI_actions.get_protocol(packet.getlayer(IP).proto, packet) == "ICMP":
                self.set_background(row_number, 220, 208, 255)

        elif packet.haslayer(ARP):
            self.captureList.setItem(row_number, 2, QTableWidgetItem(packet.getlayer(ARP).psrc))

            self.captureList.setItem(row_number, 3, QTableWidgetItem(packet.getlayer(ARP).pdst))

            self.captureList.setItem(row_number, 4,
                                     QTableWidgetItem("ARP"))

            packet_len_item = self.TableItemInt(str(len(packet)))
            self.captureList.setItem(row_number, 5, packet_len_item)

            self.captureList.update()
            self.captureList.verticalScrollBar().setSliderPosition(row_number)

            self.set_background(row_number, 245, 212, 217)

        elif packet.haslayer(IPv6):
            self.captureList.setItem(row_number, 2, QTableWidgetItem(packet.getlayer(IPv6).src))

            self.captureList.setItem(row_number, 3, QTableWidgetItem(packet.getlayer(IPv6).dst))

            self.captureList.setItem(row_number, 4,
                                     QTableWidgetItem(
                                         str(self.GUI_actions.get_protocol(packet.getlayer(IPv6).nh, packet))))

            packet_len_item = self.TableItemInt(str(len(packet)))
            self.captureList.setItem(row_number, 5, packet_len_item)

            self.captureList.update()
            self.captureList.verticalScrollBar().setSliderPosition(row_number)

            self.set_background(row_number, 204, 232, 207)

        # if the packet capture has been stopped
        if self.stopped_capture:
            # empties the table
            self.captureList.setRowCount(0)
            # resets packet counter to 1
            self.packet_number = 0
            self.captureList.update()
            self.captureList.verticalScrollBar().setSliderPosition(row_number)

        packet_total = "Packets: " + str(self.packet_number)
        self.statusBar.showMessage(packet_total)

        # increments packet number for each captured packet
        self.packet_number += 1

    # set background color for a row depending on the packet's protocol
    def set_background(self, row_number, red, green, blue):
        self.captureList.item(row_number, 0).setBackground(QColor(red, green, blue))
        self.captureList.item(row_number, 1).setBackground(QColor(red, green, blue))
        self.captureList.item(row_number, 2).setBackground(QColor(red, green, blue))
        self.captureList.item(row_number, 3).setBackground(QColor(red, green, blue))
        self.captureList.item(row_number, 4).setBackground(QColor(red, green, blue))
        self.captureList.item(row_number, 5).setBackground(QColor(red, green, blue))

    # method to display the byte version of the packet
    # currently displays data but would like, so it shows in the detail section the selected bytes
    def display_packet_data(self, packet):
        self.data.clear()
        packet_data = bytes(packet)
        hex_data = hex_packet_data(packet_data)
        datas = hex_data.split(' --- ')
        length = len(datas)
        label_num = 0
        hex_num = 1
        text_num = 2

        labels = []
        while label_num <= length - 3:
            labels.append(datas[label_num])
            label_num += 3

        hex_datas = []
        while hex_num <= length - 2:
            hex_datas.append(datas[hex_num])
            hex_num += 3


        text_datas = []
        while text_num <= length - 1:
            text_datas.append(datas[text_num])
            text_num += 3

        row_number = length / 3
        self.data.setRowCount(int(row_number))
        self.data.setColumnCount(32)

        try:
            self.data.setVerticalHeaderLabels(labels)
            current_row = 0
            while current_row < int(row_number):
                hex_data_current = hex_datas[current_row]
                hex_data_current_split = hex_data_current.split(' ')
                hex_data_helper = 0
                while hex_data_helper < 16:
                    if hex_data_helper >= len(hex_data_current_split):
                        break
                    self.data.setItem(int(current_row), hex_data_helper,
                                      QTableWidgetItem(str(hex_data_current_split[hex_data_helper])))
                    hex_data_helper += 1
                text_data_current = text_datas[current_row]
                text_data_current_split = text_data_current.split(' ')
                text_data_helper1 = 16
                text_data_helper2 = 0
                while text_data_helper1 < 32:
                    if text_data_helper2 >= len(text_data_current_split):
                        break
                    self.data.setItem(int(current_row), text_data_helper1,
                                      QTableWidgetItem(str(text_data_current_split[text_data_helper2])))
                    text_data_helper1 += 1
                    text_data_helper2 += 1
                current_row += 1
        except:
            self.data.setItem(0, 0, QTableWidgetItem("NO DATA"))

        self.actionTurnHex.setCheckable(True)
        self.actionTurnBin.setCheckable(True)
        self.actionTurnHex.setChecked(True)
        self.actionTurnBin.setChecked(False)

        self.show_in_hex = True
        self.show_in_bin = False

    def create_rightMenu(self):

        self.actionTurnBin.setCheckable(True)
        # self.actionTurnOri.setChecked(False)
        self.data_box_menu.addAction(self.actionTurnBin)

        self.actionTurnHex.setCheckable(True)
        # self.actionTurnHex.setChecked(False)
        self.data_box_menu.addAction(self.actionTurnHex)

        self.data_box_menu.popup(QCursor.pos())

    def show_data_bin(self, packet):
        self.data.clear()
        packet_data = bytes(packet)
        hex_data = hex_packet_data(packet_data)
        datas = hex_data.split(' --- ')
        length = len(datas)
        label_num = 0
        hex_num = 1
        text_num = 2
        print(datas)

        labels = []
        while label_num <= length - 3:
            labels.append(datas[label_num])
            label_num += 3

        hex_datas = []
        while hex_num <= length - 2:
            hex_datas.append(datas[hex_num])
            hex_num += 3

        text_datas = []
        while text_num <= length - 1:
            text_datas.append(datas[text_num])
            text_num += 3

        row_number = length / 3
        self.data.setRowCount(int(row_number))
        self.data.setColumnCount(32)

        try:
            self.data.setVerticalHeaderLabels(labels)
            current_row = 0
            while current_row < int(row_number):
                hex_data_current = hex_datas[current_row]
                hex_data_current_split = hex_data_current.split(' ')

                index = 0
                hex_data_fin = []
                while index < len(hex_data_current_split):
                    if hex_data_current_split[index] != '':
                        hex_data_fin.append(hex_data_current_split[index])
                    index += 1

                bin_data_current_split = []
                for x in hex_data_fin:
                    bin_data_current_split.append(bin(int(str(x), 16))[2:].zfill(2 * 4))
                # print(bin_data_current_split)

                bin_data_helper = 0
                while bin_data_helper < 16:
                    if bin_data_helper >= len(bin_data_current_split):
                        break
                    self.data.setItem(int(current_row), bin_data_helper,
                                      QTableWidgetItem(bin_data_current_split[bin_data_helper]))
                    bin_data_helper += 1
                text_data_current = text_datas[current_row]
                text_data_current_split = text_data_current.split(' ')
                text_data_helper1 = 16
                text_data_helper2 = 0
                while text_data_helper1 < 32:
                    if text_data_helper2 >= len(text_data_current_split):
                        break
                    self.data.setItem(int(current_row), text_data_helper1,
                                      QTableWidgetItem(str(text_data_current_split[text_data_helper2])))
                    text_data_helper1 += 1
                    text_data_helper2 += 1
                current_row += 1
        except:
            self.data.setItem(0, 0, QTableWidgetItem("NO DATA"))

        self.actionTurnBin.setCheckable(True)
        self.actionTurnHex.setCheckable(True)
        self.actionTurnBin.setChecked(True)
        self.actionTurnHex.setChecked(False)

        self.show_in_hex = False
        self.show_in_bin = True

    def operate_turn_hex(self):
        row = self.get_current_list_row()
        selected_packet, details = self.get_select_packet(row)
        if self.show_in_bin:
            self.display_packet_data(selected_packet)

        self.actionTurnHex.setCheckable(True)
        self.actionTurnBin.setCheckable(True)
        self.actionTurnHex.setChecked(True)
        self.actionTurnBin.setChecked(False)
        self.show_in_hex = True
        self.show_in_bin = False

    def operate_turn_bin(self):
        row = self.get_current_list_row()
        selected_packet, details = self.get_select_packet(row)
        if self.show_in_hex:
            self.show_data_bin(selected_packet)

        self.actionTurnBin.setCheckable(True)
        self.actionTurnHex.setCheckable(True)
        self.actionTurnBin.setChecked(True)
        self.actionTurnHex.setChecked(False)
        self.show_in_hex = False
        self.show_in_bin = True

    # filter autocomplete the protocol with one/some letter(s)
    def completer_operate(self, text):
        if text:
            index = self.filterBox.findText(text)
            self.filterBox.setCurrentIndex(index)

    # update the filter and completer model when model has changed
    def set_model(self, model):
        super(QComboBox, self.filterBox).setModel(model)
        self.filterBox.pFilterModel.setSourceModel(model)
        self.filterBox.completr.setModel(self.filterBox.pFilterModel)

    # update the filter and completer model when model column has changed
    def set_model_column(self, column):
        self.filterBox.completer.setCompletionColumn(column)
        self.filterBox.pFilterModel.setFilterKeyColumn(column)
        super(QComboBox, self.filterBox).setModelColumn(column)

    # use <ENTER> in filter box to select filter
    def enter_keypress(self, key):
        if key.key() == Qt.Key_Enter & key.key() == Qt.Key_Return:
            text = self.filterBox.currentText()
            index = self.filterBox.findText(text, Qt.MatchExactly | Qt.MatchCaseSensitive)
            self.filterBox.setCurrentIndex(index)
            self.filterBox.hidePopup()
            super(QComboBox, self.filterBox).enter_keypress(key)
        else:
            super(QComboBox, self.filterBox).enter_keypress(key)

    def bar_analysis(self):
        plotter = plotting.Plotting(self.GUI_actions.get_sniffed_packets())
        plotter.plot_protocol()

    def network_graph(self):
        plotter = plotting.Plotting(self.GUI_actions.get_sniffed_packets())
        plotter.network_graph()

    def mac_network_graph(self):
        plotter = plotting.Plotting(self.GUI_actions.get_sniffed_packets())
        plotter.mac_network_graph()

    def sourceaddr_plot(self):
        plotter = plotting.Plotting(self.GUI_actions.get_sniffed_packets())
        plotter.plot_source()

    def tcp_syn_flood_detect(self):
        plotter = plotting.Plotting(self.GUI_actions.get_sniffed_packets())
        self.detect = attack_detection.AttackDetection(plotter.data_frame)
        self.detect.tcp_syn_flood_detect()


# ran first and intialises PyQt window
if __name__ == '__main__':
    app = QApplication(sys.argv)
    mainWindow = Window()
    mainWindow.show()
    sys.exit(app.exec_())
