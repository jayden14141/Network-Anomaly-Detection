from PyQt5.QtWidgets import *
from scapy.all import *
from scapy.contrib.igmp import IGMP
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6ND_NA
from scapy.layers.l2 import Ether, ARP

# form_class = uic.loadUiType("subWindow.ui")[0]
from pythonGUI import sub

def hex_packet_data(packet_data):
    result = []
    digits = 4 if isinstance(packet_data, str) else 2

    for i in range(0, len(packet_data), 16):
        data = packet_data[i: i + 16]
        hexa = ' '.join([hex(x)[2:].upper().zfill(digits) for x in data])
        text = ' '.join([chr(x) if 0x20 <= x < 0x7F else '.' for x in data])
        result.append("{0:04X}".format(i) + ' --- ' + hexa.ljust(16 * (digits + 1)) + ' --- ' + "{0}".format(text))

    return ' --- '.join(result)


class SubWindow(sub.Ui_MainWindow, QMainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.packet = None
        self.detail = None
        self.length = None

        self.protocol_byte = 0

        self.tree_item = None
        self.tree_section = 0
        self.tree_dict = {}

        # TableWidget (data) for hex data
        self.data.horizontalHeader().setVisible(False)
        self.data.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.data.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.data.resizeColumnsToContents()

        self.fig.horizontalHeader().setVisible(False)
        self.fig.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.fig.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.fig.resizeColumnsToContents()

        self.info.itemClicked.connect(self.handle_clicked_tree)
        self.data.cellClicked.connect(self.handle_clicked_table)
        self.fig.cellClicked.connect(self.handle_clicked_table)

    # Wrapper function of signal clicking the tree item
    # Identifies which item was selected, and invokes selection of tree and table item
    def handle_clicked_tree(self, item):
        self.clear_selected()
        self.tree_item = item
        q_item = None
        for key, value in self.tree_dict.items():
            if item == value:
                q_item = key
        if q_item is None:
            return
        sec = q_item.strip('child')
        start, end, section = self.infer_section_byte(int(sec))

        self.make_tree_selected(0, section)
        item.setExpanded(True)
        self.make_table_selected(start, end)
    # Wrapper function of signal clicking the table item
    def handle_clicked_table(self, row, column):
        self.clear_selected()
        # start <= byte < end
        start, end, section = self.infer_type_header(16 * row + column)

        self.make_tree_selected(1, section)
        self.make_table_selected(start, end)

    # Used inv argument to infer where the function is invoked from.
    # If it's 0, it is called from the tree, otherwise, called from the table.
    def make_tree_selected(self, inv, section):
        # If the user clicks the child that's beyond the limit, return the last section of the tree
        if section > self.tree_section - 1:
            self.make_tree_selected(0, self.tree_section - 1)
            return

        # ICMPv6 Neighbour discovery _ Router Advertisement / Neighbour Advertisement
        if self.packet.haslayer(ICMPv6ND_RA) or self.packet.haslayer(ICMPv6ND_NA) \
                or self.packet.haslayer(ICMP):
            if section >= 2:
                for i in range(2, self.tree_section):
                    child = "child{}".format(i)
                    self.tree_dict[child].setSelected(True)
                    # If the function was invoked from the tree, expand what the user has clicked (Already done)
                    # If the function was invoked from the table, expand the summary
                    if i == 2:
                        self.tree_dict[child].setExpanded(True) if inv == 1 else None
            else:
                child = "child{}".format(section)
                self.tree_dict[child].setSelected(True)
                self.tree_dict[child].setExpanded(True) if inv == 1 else None

        if self.packet.haslayer(DNS) and self.packet.haslayer(UDP):
            if section >= 3:
                for i in range(3, self.tree_section):
                    child = "child{}".format(i)
                    self.tree_dict[child].setSelected(True)
                    if i == 3:
                        self.tree_dict[child].setExpanded(True) if inv == 1 else None

            else:
                child = "child{}".format(section)
                self.tree_dict[child].setSelected(True)
                self.tree_dict[child].setExpanded(True) if inv == 1 else None

        else:
            child = "child{}".format(section)
            self.tree_dict[child].setSelected(True)
            self.tree_dict[child].setExpanded(True) if inv == 1 else None

    def make_table_selected(self, start, end):
        s_row = int(start / 16)
        s_col = start % 16
        e_row = int(end / 16)
        e_col = end % 16
        if s_row == e_row:
            for i in range(s_col, e_col):
                self.data.item(s_row, i).setSelected(True)
                self.fig.item(s_row, i).setSelected(True)
        else:
            for i in range(s_row, e_row + 1):
                if i == s_row:
                    for j in range(s_col, 16):
                        self.data.item(s_row, j).setSelected(True)
                        self.fig.item(s_row, j).setSelected(True)
                elif i == e_row:
                    for j in range(0, e_col):
                        self.data.item(e_row, j).setSelected(True)
                        self.fig.item(e_row, j).setSelected(True)
                else:
                    for j in range(0, 16):
                        self.data.item(i, j).setSelected(True)
                        self.fig.item(i, j).setSelected(True)

    def clear_selected(self):
        self.statusBar().clearMessage()
        for it in self.info.selectedItems():
            it.setSelected(False)
            it.setExpanded(False)
        for it in self.data.selectedItems():
            it.setSelected(False)
        for it in self.fig.selectedItems():
            it.setSelected(False)

    # Helper function that identifies particular section in qTreeWidget
    def infer_section_byte(self, section):
        if section == 0:
            return self.infer_type_header(0)
        elif section == 1:
            return self.infer_type_header(14)
        elif section == 2:
            if self.packet.haslayer(IP):
                return self.infer_type_header(34)
            elif self.packet.haslayer(IPv6):
                return self.infer_type_header(54)
            elif self.packet.haslayer(ARP):
                return self.infer_type_header(42)
        else:
            return self.infer_type_header(self.length - 1)

    # Helper function that identifies fields by byte in qTableWidget
    def infer_type_header(self, byte):
        # Ethernet bytes
        if 0 <= byte <= 13:
            self.statusBar().showMessage("Byte 0-13: Ethernet header")
            return 0, 14, 0

        # IPv4 / IPv6 / ARP bytes
        if self.packet.haslayer(IP):
            if 14 <= byte <= 33:
                self.protocol_byte = 33
                self.statusBar().showMessage("Byte 14-33: IPv4 header")
                return 14, 34, 1
        elif self.packet.haslayer(IPv6):
            if 14 <= byte <= 53:
                self.protocol_byte = 53
                self.statusBar().showMessage("Byte 14-53: IPv6 header")
                return 14, 54, 1
        # ARP packets
        else:
            if 14 <= byte <= 41:
                self.protocol_byte = 41
                self.statusBar().showMessage("Byte 14-41: ARP header")
                return 14, 42, 1

        # UDP / TCP / ICMP / IGMP bytes
        if self.packet.haslayer(UDP):
            last = self.protocol_byte
            if (last + 1) <= byte <= (last + 8):
                self.statusBar().showMessage("Byte "+str(last+1)+"-"+str(last+8)+": UDP header")
                return last + 1, last + 9, 2
            # DNS / Raw
            else:
                if self.packet.haslayer(DNS):
                    self.statusBar().showMessage("Byte " + str(last + 9) + "-" + str(self.length) + ": DNS header")
                else:
                    self.statusBar().showMessage("Byte " + str(last + 9) + "-" + str(self.length) + ": Data")
                return last + 9, self.length, 3

        elif self.packet.haslayer(TCP):
            last = self.protocol_byte
            if (last + 1) <= byte <= (last + 20):
                if self.packet.haslayer(Raw):
                    self.statusBar().showMessage("Byte " + str(last + 1) + "-" + str(last+21) + ": TCP header")
                    return last + 1, last + 21, 2
                else:
                    self.statusBar().showMessage("Byte " + str(last + 1) + "-" + str(last + 21) + ": TCP header")
                    return last + 1, self.length, 2
            # Padding / Raw
            else:
                self.statusBar().showMessage("Byte " + str(last + 21) + "-" + str(self.length) + ": Data")
                return last + 21, self.length, 3

        elif self.packet.haslayer(ICMP):
            last = self.protocol_byte
            if byte > last:
                self.statusBar().showMessage("Byte " + str(last + 1) + "-" + str(self.length) + ": ICMP header")
                return last + 1, self.length, 2

        elif self.packet.haslayer(IGMP):
            last = self.protocol_byte
            if byte > last:
                self.statusBar().showMessage("Byte " + str(last + 1) + "-" + str(self.length) + ": IGMP header")
                return last + 1, self.length, 2

        else:
            last = self.protocol_byte
            if byte > last:
                if self.packet.haslayer(ARP):
                    self.statusBar().showMessage("Byte " + str(last + 1) + "-" + str(self.length) + ": Padding")
                    return last + 1, self.length, 2
                self.statusBar().showMessage("Byte " + str(last + 1) + "-" + str(self.length) + ": Data")
                return last + 1, self.length, 3

    def display_packet_detail(self, detail):
        self.detail = detail
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
        print(self.packet.layers())
        self.tree_section = root_amount
        self.add_packet_summary(root_name, root_amount)
        for i in range(root_amount):
            name = 'child{}'.format(i)
            self.tree_dict[name] = QTreeWidgetItem(self.info)
            self.info.setSelectionMode(QTreeWidget.MultiSelection)
            root_arr.append(self.tree_dict[name])
            root_arr[i].setText(0, root_name[i])
            # print(name + " : " + str(self.tree_dict[name]))

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

    def add_packet_summary(self, root_name, num):
        for i in range(num):
            if root_name[i] == "Ethernet":
                root_name[i] = "Ethernet, Src: " + str(self.packet[Ether].src) + ",  Dst: " + str(
                    self.packet[Ether].dst)
            elif root_name[i] == "IP":
                root_name[i] = "Internet Protocol Version 4, Src: " + \
                               str(self.packet[IP].src) + ",  Dst: " + str(self.packet[IP].dst)
            elif root_name[i] == "IPv6":
                root_name[i] = "Internet Protocol Version 6, Src: " + \
                               str(self.packet[IPv6].src) + ",  Dst: " + str(self.packet[IPv6].dst)
            elif root_name[i] == "UDP":
                root_name[i] = "User Datagram Protocol, Src Port: " + \
                               str(self.packet[UDP].sport) + ",  Dst Port: " + str(self.packet[UDP].dport)
            elif root_name[i] == "TCP":
                root_name[i] = "Transmission Control Protocol, Src Port: " + \
                               str(self.packet[TCP].sport) + ",  Dst Port: " + str(self.packet[TCP].dport)
            elif root_name[i] == "ARP":
                if self.packet[ARP].op == 2:
                    root_name[i] = "Address Resolution Protocol (Reply)"
                else:
                    root_name[i] = "Address Resolution Protocol (Request)"
            elif root_name[i] == "DNS":
                if self.packet[DNS].opcode == 0:
                    root_name[i] = "Domain Name System (Query)"
                else:
                    root_name[i] = "Domain Name System (Response)"

    def display_packet_data(self, packet):
        self.packet = packet
        self.length = len(packet)
        print(self.length)
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
        self.data.setColumnCount(16)

        self.fig.setRowCount(int(row_number))
        self.fig.setColumnCount(16)

        try:
            self.data.setVerticalHeaderLabels(labels)
            current_row = 0
            while current_row < int(row_number):
                # print(str(hex_datas[current_row]))
                hex_data_current = hex_datas[current_row]
                hex_data_current_split = hex_data_current.split(' ')
                text_data_current = text_datas[current_row]
                text_data_current_split = text_data_current.split(' ')
                # print(hex_data_current_split)
                hex_data_helper = 0
                text_data_helper = 0
                while hex_data_helper < 16:
                    self.data.setItem(int(current_row), hex_data_helper,
                                      QTableWidgetItem(str(hex_data_current_split[hex_data_helper])))
                    self.fig.setItem(int(current_row), text_data_helper,
                                     QTableWidgetItem(str(text_data_current_split[text_data_helper])))
                    hex_data_helper += 1
                    text_data_helper += 1
                current_row += 1
                # print(current_row)
        except:
            return
            # return


if __name__ == "__main__":
    app = QApplication(sys.argv)
    myWindow = SubWindow()
    myWindow.show()
    app.exec_()
