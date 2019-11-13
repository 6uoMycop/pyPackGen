# This Python file uses the following encoding: utf-8
from tkinter import *
from tkinter.ttk import *
from scapy.layers.inet import IP, UDP, TCP, ICMP, IPOption
from scapy.layers.l2 import Ether
from scapy.data import load_ethertypes
from scapy.all import *
from scapy.arch.windows import show_interfaces
from scapy.layers.inet6 import IPv6
from scapy.dadict import DADict
#from getmac import get_mac_address

g_currentInterface = -1

class backendClass:
    def __init__(self):
        self.listPackets = list()
        #self.interfaces = show_interfaces()

    def getNumberOfPackets(self):
        return len(self.listPackets)

    #def createPacket(self):
        #self.qPackets.put(TCP)
        #packet = TCP()

    def getInterfaces(self):
        rawInterfaces = get_windows_if_list()
        listInterfaces = list()
        for item in rawInterfaces:
            listInterfaces.append(item)
        return listInterfaces
