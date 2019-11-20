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
    # ^^^ __init__ ^^^

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
    # ^^^ saveExit ^^^

    def cancelExit(self):
        self.reject()
    # ^^^ cancelExit ^^^
# ^^^ class DialogWindow ^^^



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
        #UDP
        self.ui.pushButton_saveUDP.clicked.connect(self.saveUDP)
        #ICMP
        self.ui.pushButton_saveICMP.clicked.connect(self.saveICMP)
        #IP
        self.ui.pushButton_saveIP.clicked.connect(self.saveIP)

        self.ui.pushButton_sendAll.clicked.connect(self.sendAllPackets)
    # ^^^ __init__ ^^^

    def addPacket(self):
        self.ui.tableWidget_PacketsQueue.insertRow(self.backend.getNumberOfPackets())
    # ^^^ addPacket ^^^

    def saveTCP(self):
        if(self.ui.checkBox_autoDataOffsetTCP.isChecked()):
            offset = None
        else:
            offset = self.ui.lineEdit_dataOffsetTCP.text()

        if(self.ui.checkBox_autoReservedTCP.isChecked()):
            reserved = '0'
        else:
            reserved = self.ui.lineEdit_reservedTCP.text()

        if(self.ui.checkBox_autoChecksumTCP.isChecked()):
            checksum = None
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
                self.ui.plainTextEdit_dataTCP.toPlainText(),
                None
                    if self.ui.tableWidget_PacketsQueue.currentRow() == self.backend.getNumberOfPackets()
                    else self.ui.tableWidget_PacketsQueue.currentRow()
            )
            self.drawPacketInQueue(newPacket)
        except MyPacketError as e:
           self.ui.statusbar.showMessage('Внимание! ' + e.message + ' Пакет не был сохранен.')

    # ^^^ saveTCP ^^^

    def saveUDP(self):
        if(self.ui.checkBox_autoLengthUDP.isChecked()):
            datagramLength = ''
        else:
            datagramLength = self.ui.lineEdit_lengthUDP.text()

        if(self.ui.checkBox_autoChecksumUDP.isChecked()):
            checksum = ''
        else:
            checksum = self.ui.lineEdit_checksumUDP.text()

        try:
            newPacket = self.backend.createUDP(
                self.ui.lineEdit_srcPortUDP.text(),
                self.ui.lineEdit_dstPortUDP.text(),
                datagramLength,
                checksum,
                self.ui.plainTextEdit_dataUDP.toPlainText(),
                None
                    if self.ui.tableWidget_PacketsQueue.currentRow() == self.backend.getNumberOfPackets()
                    else self.ui.tableWidget_PacketsQueue.currentRow()
            )
            self.drawPacketInQueue(newPacket)
        except MyPacketError as e:
           self.ui.statusbar.showMessage('Внимание! ' + e.message + ' Пакет не был сохранен.')
    # ^^^ saveUDP ^^^

    def saveICMP(self):
        if(self.ui.checkBox_autoChecksumICMP.isChecked()):
            checksum = ''
        else:
            checksum = self.ui.lineEdit_checksumICMP.text()

        try:
            if self.ui.comboBox_typeICMP.currentIndex() == 0: # manual
                type = self.ui.lineEdit_typeICMP.text()
            elif self.ui.comboBox_typeICMP.currentIndex() == 1: # echo-request
                type = 8
            elif self.ui.comboBox_typeICMP.currentIndex() == 2: # echo-reply
                type = 0
            else:
                raise MyPacketError('Ошибка.')

            newPacket = self.backend.createICMP(
                type,
                self.ui.lineEdit_codeICMP.text(),
                checksum,
                self.ui.lineEdit_identifierICMP.text(),
                self.ui.lineEdit_seqICMP.text(),
                self.ui.plainTextEdit_dataICMP.toPlainText(),
                None
                    if self.ui.tableWidget_PacketsQueue.currentRow() == self.backend.getNumberOfPackets()
                    else self.ui.tableWidget_PacketsQueue.currentRow()
            )
            self.drawPacketInQueue(newPacket)
        except MyPacketError as e:
           self.ui.statusbar.showMessage('Внимание! ' + e.message + ' Пакет не был сохранен.')
    # ^^^ saveICMP ^^^

    def saveIP(self):
        print('placeholder')
    # ^^^ saveIP ^^^

    def showInterfaceDialog(self):
        self.dialogInterface.exec_()
    # ^^^ showInterfaceDialog ^^^

    def sendAllPackets(self):
        self.backend.sendAll(self.ui.statusbar)
    # ^^^ sendAllPackets ^^^

    def drawPacketInQueue(self, packet):
        self.ui.tableWidget_PacketsQueue.setItem(self.ui.tableWidget_PacketsQueue.currentRow(), 0, QtWidgets.QTableWidgetItem(str(self.backend.getType   (packet)))) # type
        self.ui.tableWidget_PacketsQueue.setItem(self.ui.tableWidget_PacketsQueue.currentRow(), 1, QtWidgets.QTableWidgetItem(str(self.backend.getSrcAddr(packet)))) # source address
        self.ui.tableWidget_PacketsQueue.setItem(self.ui.tableWidget_PacketsQueue.currentRow(), 2, QtWidgets.QTableWidgetItem(str(self.backend.getDstAddr(packet)))) # remote address
        self.ui.tableWidget_PacketsQueue.setItem(self.ui.tableWidget_PacketsQueue.currentRow(), 3, QtWidgets.QTableWidgetItem(str(self.backend.getSrcPort(packet)))) # source port
        self.ui.tableWidget_PacketsQueue.setItem(self.ui.tableWidget_PacketsQueue.currentRow(), 4, QtWidgets.QTableWidgetItem(str(self.backend.getDstPort(packet)))) # remote port
    # ^^^ drawPacketInQueue ^^^

    def selectPacket(self, row, column):
        self.packetIndex = row
        self.ui.tabWidget_setPacket.setEnabled(True)
        #TODO: fill in all fields
    # ^^^ selectPacket ^^^
# ^^^ class MainWindow ^^^

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)

    window = MainWindow()
    window.show()

    sys.exit(app.exec_())
