# This Python file uses the following encoding: utf-8
import sys
#from PySide2.QtWidgets import QApplication, QMainWindow
from PySide2 import QtWidgets
from PySide2.QtCore import QFile
from ui_mainwindow import Ui_MainWindow
from ui_dialog import Ui_Dialog
from backendClass import *

class DialogWindow(QtWidgets.QDialog):
    def __init__(self, listInterfaces):
        super(DialogWindow, self).__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.listIfaces = listInterfaces

        for item in listInterfaces:
            self.ui.comboBox_interfaces.addItem(item.get('name'))

        self.ui.buttonBox.accepted.connect(self.saveExit)
        self.ui.buttonBox.rejected.connect(self.cancelExit)

    def saveExit(self):
        self.setResult(self.ui.comboBox_interfaces.currentIndex())
        global g_currentInterface
        g_currentInterface = self.ui.comboBox_interfaces.currentIndex()
        if g_currentInterface == -1:
            self.ui.label_currentInterface.setText("Не выбран")
        else:
            self.ui.label_currentInterface.setText(self.listIfaces[g_currentInterface].get('name'))
        self.accept()

    def cancelExit(self):
        self.reject()


class MainWindow(QtWidgets.QMainWindow):

    def __init__(self):
        super(MainWindow, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.tableWidget_PacketsQueue.horizontalHeader().setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        self.ui.tableWidget_PacketsQueue.horizontalHeader().setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
        self.ui.tableWidget_PacketsQueue.horizontalHeader().setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeToContents)
        self.ui.tableWidget_PacketsQueue.horizontalHeader().setSectionResizeMode(3, QtWidgets.QHeaderView.ResizeToContents)
        self.ui.tableWidget_PacketsQueue.horizontalHeader().setSectionResizeMode(4, QtWidgets.QHeaderView.ResizeToContents)

        self.ui.actionSetInterface.triggered.connect(self.showInterfaceDialog)
        self.ui.pushButton_addPacket.clicked.connect(self.addPacket)

        self.backend = backendClass()
        self.dialogInterface = DialogWindow(self.backend.getInterfaces())


    def showInterfaceDialog(self):
        self.dialogInterface.exec_()

    def addPacket(self):
        self.ui.tableWidget_PacketsQueue.insertRow(self.backend.getNumberOfPackets())





if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)

    window = MainWindow()
    window.show()

    sys.exit(app.exec_())
