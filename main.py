# This Python file uses the following encoding: utf-8
import sys
from PySide2.QtWidgets import QApplication, QMainWindow, QHeaderView, QTableWidgetItem
from PySide2 import QtWidgets
#from PySide2.QtCore import QFile
from ui_mainwindow import Ui_MainWindow
from ui_dialog import Ui_Dialog
from backendClass import *
import pdb

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



class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        for i in range (0, self.ui.tableWidget_PacketsQueue.columnCount()):
            self.ui.tableWidget_PacketsQueue.horizontalHeader().setSectionResizeMode(i, QHeaderView.ResizeToContents)
        for i in range (0, self.ui.tableWidget_optionsTCP.columnCount()):
            self.ui.tableWidget_optionsTCP.horizontalHeader().setSectionResizeMode(i, QHeaderView.ResizeToContents)

        self.backend = backendClass()
        self.dialogInterface = DialogWindow(self.backend)
        self.packetIndex = -1; # index of current chosen packet which's fields are shown on the right side

        self.ui.actionSetInterface.triggered.connect(self.showInterfaceDialog)
        self.ui.pushButton_addPacket.clicked.connect(self.addPacket)
        self.ui.tableWidget_PacketsQueue.cellDoubleClicked.connect(self.selectPacket)

        self.ui.pushButton_deleteOptionTCP.clicked.connect(self.removeOptionRowTCP)
        self.ui.pushButton_addOptionTCP   .clicked.connect(self.addOptionRowTCP)

        #TCP
        self.ui.pushButton_saveTCP.clicked.connect(self.saveTCP)
        #UDP
        self.ui.pushButton_saveUDP.clicked.connect(self.saveUDP)
        #ICMP
        self.ui.pushButton_saveICMP.clicked.connect(self.saveICMP)
        #IP
        self.ui.pushButton_saveIP.clicked.connect(self.saveIP)
        #Ether
        self.ui.pushButton_saveEthernet.clicked.connect(self.saveEthernet)


        self.ui.pushButton_sendAll.clicked.connect(self.sendAllPackets)
    # ^^^ __init__ ^^^

    def addPacket(self):
        self.ui.tableWidget_PacketsQueue.insertRow(self.backend.getNumberOfPackets())
    # ^^^ addPacket ^^^

    def addOptionRowIP(self):
        self.ui.tableWidget_optionsIP.insertRow(0)
    # ^^^ addOptionRowIP ^^^
    def addOptionRowTCP(self):
        self.ui.tableWidget_optionsTCP.insertRow(0)
    # ^^^ addOptionRowTCP ^^^
    def removeOptionRowIP(self):
        self.ui.tableWidget_optionsIP.removeRow(0)
    # ^^^ deleteOptionRowIP ^^^
    def removeOptionRowTCP(self):
        self.ui.tableWidget_optionsTCP.removeRow(0)
    # ^^^ deleteOptionRowTCP ^^^

    def getOptionsFromTable(self, tableWidget):
        options = []
        for i in range (0, tableWidget.rowCount()):
            options.append((tableWidget.item(i, 0).text(), tableWidget.item(i, 1).text(), tableWidget.item(i, 2).text()))
        print(options)
        return options
    # ^^^ getOptionsFromTable ^^^

    def saveTCP(self):
        options = self.getOptionsFromTable(self.ui.tableWidget_optionsTCP)

        if self.ui.checkBox_autoDataOffsetTCP.isChecked():
            offset = None
        else:
            offset = self.ui.lineEdit_dataOffsetTCP.text()

        if self.ui.checkBox_autoReservedTCP.isChecked():
            reserved = '0'
        else:
            reserved = self.ui.lineEdit_reservedTCP.text()

        if self.ui.checkBox_autoChecksumTCP.isChecked():
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
                options,
                self.ui.plainTextEdit_dataTCP.toPlainText(),
                None
                    if self.ui.tableWidget_PacketsQueue.currentRow() == self.backend.getNumberOfPackets()
                    else self.ui.tableWidget_PacketsQueue.currentRow()
            )
            self.drawPacketInQueue()
        except MyPacketError as e:
           self.ui.statusbar.showMessage('Внимание! ' + e.message + ' Пакет не был сохранен.')

    # ^^^ saveTCP ^^^

    def saveUDP(self):
        if self.ui.checkBox_autoLengthUDP.isChecked():
            datagramLength = ''
        else:
            datagramLength = self.ui.lineEdit_lengthUDP.text()

        if self.ui.checkBox_autoChecksumUDP.isChecked():
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
                self.ui.tableWidget_PacketsQueue.currentRow()
            )
            self.drawPacketInQueue()
        except MyPacketError as e:
           self.ui.statusbar.showMessage('Внимание! ' + e.message + ' Пакет не был сохранен.')
    # ^^^ saveUDP ^^^

    def saveICMP(self):
        if self.ui.checkBox_autoChecksumICMP.isChecked():
            checksum = ''
        else:
            checksum = self.ui.lineEdit_checksumICMP.text()

        if self.ui.checkBox_autoCodeICMP.isChecked():
            code = '0'
        else:
            code = self.ui.lineEdit_codeICMP.text()


        try:
            if self.ui.comboBox_typeICMP.currentIndex() == 0: # manual
                type = self.ui.lineEdit_typeICMP.text()
            elif self.ui.comboBox_typeICMP.currentIndex() == 1: # echo-request
                type = '8'
            elif self.ui.comboBox_typeICMP.currentIndex() == 2: # echo-reply
                type = '0'
            else:
                raise MyPacketError('Ошибка.')

            newPacket = self.backend.createICMP(
                type,
                code,
                checksum,
                self.ui.lineEdit_identifierICMP.text(),
                self.ui.lineEdit_seqICMP.text(),
                self.ui.plainTextEdit_dataICMP.toPlainText(),
                self.ui.tableWidget_PacketsQueue.currentRow()
            )
            self.drawPacketInQueue()
        except MyPacketError as e:
           self.ui.statusbar.showMessage('Внимание! ' + e.message + ' Пакет не был сохранен.')
    # ^^^ saveICMP ^^^

    def saveIP(self):
        if self.ui.checkBox_autoChecksumIP.isChecked():
            checksum = ''
        else:
            checksum = self.ui.lineEdit_checksumIP.text()

        if self.ui.checkBox_autoIHL.isChecked():
            IHL = ''
        else:
            IHL = self.ui.lineEdit_IHL.text()

        if self.ui.checkBox_autoTotalLengthIP.isChecked():
            length = ''
        else:
            length = self.ui.lineEdit_totalLengthIP.text()

        if self.ui.checkBox_autoOffsetIP.isChecked():
            offset = ''
        else:
            offset = self.ui.lineEdit_fragmentOffsetIP.text()

        if self.ui.checkBox_autoIDataP.isChecked():
            payload = ''
        else:
            payload = self.ui.plainTextEdit_dataIP.toPlainText()

        try:
            if self.ui.comboBox_versionIP.currentIndex() == 0: # manual
                version = self.ui.lineEdit_typeICMP.text()
            elif self.ui.comboBox_versionIP.currentIndex() == 1: # IPv4
                version = 4
            else:
                raise MyPacketError('Ошибка.')

            if self.ui.comboBox_protocolIP.currentIndex() == 0: # manual
                protocol = self.ui.lineEdit_protocolIP.text()
            elif self.ui.comboBox_protocolIP.currentIndex() == 1: # TCP
                protocol = 6
            elif self.ui.comboBox_protocolIP.currentIndex() == 2: # UDP
                protocol = 17
            elif self.ui.comboBox_protocolIP.currentIndex() == 3: # ICMP
                protocol = 1
            else:
                raise MyPacketError('Ошибка.')

            newPacket = self.backend.createIP(
                version,
                IHL,
                self.ui.lineEdit_DSCP.text(),
                length,
                self.ui.lineEdit_identificationIP.text(),
                self.ui.checkBox_reservedFlagIP.isChecked(),
                self.ui.checkBox_dontFragmentFlagIP.isChecked(),
                self.ui.checkBox_moreFragmentsFlagIP.isChecked(),
                offset,
                self.ui.lineEdit_timeToLiveIP.text(),
                protocol,
                checksum,
                self.ui.lineEdit_srcAddrIP.text(),
                self.ui.lineEdit_dstAddrIP.text(),
                self.ui.plainTextEdit_optionsIP.toPlainText(),
                payload,
                self.ui.tableWidget_PacketsQueue.currentRow()
            )
            self.drawPacketInQueue()
        except MyPacketError as e:
           self.ui.statusbar.showMessage('Внимание! ' + e.message + ' Пакет не был сохранен.')
    # ^^^ saveIP ^^^

    def saveEthernet(self):
        try:
            if self.ui.comboBox_etherType.currentIndex() == 0: # manual
                etherType = self.ui.lineEdit_etherType.text()
            elif self.ui.comboBox_etherType.currentIndex() == 1: # IPv4
                etherType = '0800'
            else:
                raise MyPacketError('Ошибка.')

            newPacket = self.backend.createEthernet(
                etherType,
                self.ui.tableWidget_PacketsQueue.currentRow()
                #None if self.ui.tableWidget_PacketsQueue.currentRow() == self.backend.getNumberOfPackets()
                #    else self.ui.tableWidget_PacketsQueue.currentRow()
            )
            self.drawPacketInQueue()
        except MyPacketError as e:
           self.ui.statusbar.showMessage('Внимание! ' + e.message + ' Пакет не был сохранен.')
    # ^^^ saveEthernet ^^^

    def showInterfaceDialog(self):
        self.dialogInterface.exec_()
    # ^^^ showInterfaceDialog ^^^

    def sendAllPackets(self):
        ret = self.backend.sendAll(self.ui.statusbar, self.ui.radioButton_ifDeleteAll.isChecked())
        if ret == 0 and self.ui.radioButton_ifDeleteAll.isChecked():
            self.ui.tableWidget_PacketsQueue.setRowCount(0)
    # ^^^ sendAllPackets ^^^

    def drawPacketInQueue(self):
        index = self.ui.tableWidget_PacketsQueue.currentRow()
        packet = self.backend.listPackets[index]
        print('draw ind: ' + str(index))
        #print(str(packet))
        self.ui.tableWidget_PacketsQueue.setItem(index, 0, QTableWidgetItem(str(self.backend.getType     (packet)))) # type
        self.ui.tableWidget_PacketsQueue.setItem(index, 1, QTableWidgetItem(str(self.backend.getSrcAddr  (packet)))) # source address
        self.ui.tableWidget_PacketsQueue.setItem(index, 2, QTableWidgetItem(str(self.backend.getDstAddr  (packet)))) # remote address
        self.ui.tableWidget_PacketsQueue.setItem(index, 3, QTableWidgetItem(str(self.backend.getSrcPort  (packet)))) # source port
        self.ui.tableWidget_PacketsQueue.setItem(index, 4, QTableWidgetItem(str(self.backend.getDstPort  (packet)))) # remote port
        self.ui.tableWidget_PacketsQueue.setItem(index, 5, QTableWidgetItem(str(self.backend.getEtherType(self.backend.listPackets[index])))) # EtherType
    # ^^^ drawPacketInQueue ^^^

    def selectPacket(self, row, column):
        self.packetIndex = row
        self.ui.tabWidget_setPacket.setEnabled(True)
        #TODO: fill in all fields
    # ^^^ selectPacket ^^^
# ^^^ class MainWindow ^^^

if __name__ == "__main__":
    app = QApplication(sys.argv)

    window = MainWindow()
    window.show()

    sys.exit(app.exec_())
