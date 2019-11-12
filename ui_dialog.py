# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'dialog.ui',
# licensing of 'dialog.ui' applies.
#
# Created: Tue Nov 12 23:05:11 2019
#      by: pyside2-uic  running on PySide2 5.13.2
#
# WARNING! All changes made in this file will be lost!

from PySide2 import QtCore, QtGui, QtWidgets

class Ui_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(381, 106)
        self.widget = QtWidgets.QWidget(Dialog)
        self.widget.setGeometry(QtCore.QRect(12, 6, 361, 91))
        self.widget.setObjectName("widget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.widget)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setObjectName("verticalLayout")
        self.label = QtWidgets.QLabel(self.widget)
        self.label.setObjectName("label")
        self.verticalLayout.addWidget(self.label)
        self.comboBox_interfaces = QtWidgets.QComboBox(self.widget)
        self.comboBox_interfaces.setObjectName("comboBox_interfaces")
        self.verticalLayout.addWidget(self.comboBox_interfaces)
        self.buttonBox = QtWidgets.QDialogButtonBox(self.widget)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.verticalLayout.addWidget(self.buttonBox)

        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(QtWidgets.QApplication.translate("Dialog", "Dialog", None, -1))
        self.label.setText(QtWidgets.QApplication.translate("Dialog", "Выберите сетевой интерфейс:", None, -1))

