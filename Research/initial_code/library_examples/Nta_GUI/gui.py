# -------------------------------
# This code uses Virtual Environment
# This code uses: python 3.8
#                 PyQt5, which is an external python library.


# To install packages related to GUI,
# INSTALL/ ACTIVATE the virtual environment!!

# To install venv => 'python3 -m venv venv'

# To Activate => 'source venv/bin/activate' for Linux, Mac
#             => 'call venv/scripts/activate.bat' for Windows
# Then, install/modify the packages

# Install PyQt5 => 'pip install PyQt5'

# If your done, just type 'deactivate'

import sys
from PyQt5.QtWidgets import QApplication, QWidget

# Returns MyApp object
class NTA(QWidget):

    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Network Traffic Analysis")
        # Decides the absolute position of the GUI within the screen
        self.move(300, 300)
        # Decides the sieze of the widget itself
        self.resize(400, 200)
        # Shows the widget on the screen.
        self.show()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = NTA()
    sys.exit(app.exec_())