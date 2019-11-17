# This Python file uses the following encoding: utf-8
import sys
#from PySide2.QtWidgets import QApplication, QMainWindow
from PySide2 import QtWidgets
from PySide2.QtCore import QFile
from ui_mainwindow import Ui_MainWindow
from ui_dialog import Ui_Dialog
from backendClass import *


class DialogWindow(QtWidgets.QDialog):
    def __init__(self, backend):
        super(DialogWindow, self).__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.listInterfaces = backend.getInterfaces()
        self.backend = backend

        for item in self.listInterfaces:
            tmp = item.get('name') + ' // ' + item.get('mac')
            self.ui.comboBox_interfaces.addItem(tmp)

        self.ui.buttonBox.accepted.connect(self.saveExit)
        self.ui.buttonBox.rejected.connect(self.cancelExit)

    def saveExit(self):
        self.setResult(self.ui.comboBox_interfaces.currentIndex())
        self.backend.currentInterface.index     = self.ui.comboBox_interfaces.currentIndex()
        print(': ' + str(self.backend.currentInterface.index))
        if self.backend.currentInterface.index == -1:
            self.ui.label_currentInterface.setText("Не выбран")
        else:
            self.backend.currentInterface.interface = self.listInterfaces[self.ui.comboBox_interfaces.currentIndex()]
            self.ui.label_currentInterface.setText(self.backend.currentInterface.interface.get('name') + ' // ' + self.backend.currentInterface.interface.get('mac'))
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

        self.backend = backendClass()
        self.dialogInterface = DialogWindow(self.backend)
        self.packetIndex = -1; # index of current chosen packet which's fields are shown on the right side

        self.ui.actionSetInterface.triggered.connect(self.showInterfaceDialog)
        self.ui.pushButton_addPacket.clicked.connect(self.addPacket)
        self.ui.tableWidget_PacketsQueue.cellDoubleClicked.connect(self.selectPacket)

        #TCP
        self.ui.pushButton_saveTCP.clicked.connect(self.saveTCP)


        self.ui.pushButton_sendAll.clicked.connect(self.sendAllPackets)


    def addPacket(self):
        self.ui.tableWidget_PacketsQueue.insertRow(self.backend.getNumberOfPackets())

    def saveTCP(self):
        if(self.ui.checkBox_autoDataOffsetTCP.isChecked()):
            offset = 0 # TODO
        else:
            offset = self.ui.lineEdit_dataOffsetTCP.text()

        if(self.ui.checkBox_autoReservedTCP.isChecked()):
            reserved = 0 # TODO
        else:
            reserved = self.ui.lineEdit_reservedTCP.text()

        if(self.ui.checkBox_autoChecksumTCP.isChecked()):
            checksum = None # check it
        else:
            checksum = self.ui.lineEdit_checksumTCP.text()

        try:
            newPacket = self.backend.createTCP(
                self.ui.lineEdit_srcPortTCP.text(),
                self.ui.lineEdit_dstPortTCP.text(),
                self.ui.lineEdit_seqTCP.text(),
                self.ui.lineEdit_ackTCP.text(),
                offset,
                reserved,
                self.ui.checkBox_urgTCP.isChecked(),
                self.ui.checkBox_ackTCP.isChecked(),
                self.ui.checkBox_pshTCP.isChecked(),
                self.ui.checkBox_rstTCP.isChecked(),
                self.ui.checkBox_synTCP.isChecked(),
                self.ui.checkBox_finTCP.isChecked(),
                self.ui.lineEdit_windowSizeTCP.text(),
                checksum,
                self.ui.lineEdit_urgentPointerTCP.text(),
                self.ui.plainTextEdit_optionsTCP.toPlainText(),
                self.ui.plainTextEdit_dataTCP.toPlainText()
            )

            self.ui.tableWidget_PacketsQueue.setItem(self.backend.getNumberOfPackets() - 1, 0, QtWidgets.QTableWidgetItem(str(self.backend.getType   (newPacket)))) # type
            self.ui.tableWidget_PacketsQueue.setItem(self.backend.getNumberOfPackets() - 1, 1, QtWidgets.QTableWidgetItem(str(self.backend.getSrcAddr(newPacket)))) # source address
            self.ui.tableWidget_PacketsQueue.setItem(self.backend.getNumberOfPackets() - 1, 2, QtWidgets.QTableWidgetItem(str(self.backend.getDstAddr(newPacket)))) # remote address
            self.ui.tableWidget_PacketsQueue.setItem(self.backend.getNumberOfPackets() - 1, 3, QtWidgets.QTableWidgetItem(str(self.backend.getSrcPort(newPacket)))) # source port
            self.ui.tableWidget_PacketsQueue.setItem(self.backend.getNumberOfPackets() - 1, 4, QtWidgets.QTableWidgetItem(str(self.backend.getDstPort(newPacket)))) # remote port

        except MyPacketError as e:
           self.ui.statusbar.showMessage('Внимание! ' + e.message + ' Пакет не был сохранен.')

    def showInterfaceDialog(self):
        self.dialogInterface.exec_()

    def sendAllPackets(self):
        self.backend.sendAll(self.ui.statusbar)

    def selectPacket(self, row, column):
        self.packetIndex = row
        self.ui.tabWidget_setPacket.setEnabled(True)
        #TODO: fill in all fields



if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)

    window = MainWindow()
    window.show()

    sys.exit(app.exec_())
