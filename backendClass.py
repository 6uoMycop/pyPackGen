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
from getmac import get_mac_address


class MyPacketError(RuntimeError):
    '''raise this when there's a missing argument'''
    def __init__(self, msg):
        self.message = msg

class interfaceClass:
    def __init__(self):
        self.index = -1
        self.interface = None

#class packetClass:
#    def __init__(self):
#        self.type = None
#        self.raw = None
#    def __init__(self, type, raw, incapsulated=None):
#        self.type = type
#        self.raw = raw
#        if type == 'IP':
#            self.underLayerPacket = incapsulated
#            #TODO: add fields
#        elif type == 'TCP':
#            #TODO: add fields
#            self.srcPort =
#        #elif type == 'UDP':
#        #    #TODO: add fields
#        #elif type == 'ICMP':
#        #    #TODO: add fields


class backendClass:
    def __init__(self):
        self.listPackets = list()
        self.currentInterface = interfaceClass()
        self.rawInterfaces = get_windows_if_list()

    def getNumberOfPackets(self):
        return len(self.listPackets)

    def createTCP(self, srcPort, dstPort, seqNum, ackNum, offset, reserved, urg, ack, psh, rst, syn, fin, window, checksum, urgPtr, options, data):
        print("src:      " + srcPort)
        print("dst:      " + dstPort)
        print("seq:      " + seqNum)
        print("ack:      " + ackNum)
        print("offset:   " + offset)
        print("reserved: " + str(reserved))
        print("urg:      " + str(urg))
        print("ack:      " + str(ack))
        print("psh:      " + str(psh))
        print("rst:      " + str(rst))
        print("syn:      " + str(syn))
        print("fin:      " + str(fin))
        print("window:   " + window)
        print("checksum: " + str(checksum))
        print("urg ptr:  " + urgPtr)
        print("options:  " + options)
        print("data:     " + data)

        flagsTCP = 0;
        flagsTCP += 0b00000001 if urg else 0
        flagsTCP += 0b00000010 if ack else 0
        flagsTCP += 0b00000100 if psh else 0
        flagsTCP += 0b00001000 if rst else 0
        flagsTCP += 0b00010000 if syn else 0
        flagsTCP += 0b00100000 if fin else 0

        print(bin(flagsTCP))

        if srcPort == '':
            raise MyPacketError('Не указан порт отправки.')
        if dstPort == '':
            raise MyPacketError('Не указан порт назначения.')
        if seqNum == '':
            raise MyPacketError('Не указан SEQ.')
        if ackNum == '':
            raise MyPacketError('Не указан ACK.')
        if offset == '':
            raise MyPacketError('Не указано смещение данных.')
        if reserved == '':
            raise MyPacketError('Не указано значение зарезервированного поля.')
        if window == '':
            raise MyPacketError('Не указан размер окна.')
        if checksum == '':
            raise MyPacketError('Не указана контрольная сумма.')
        if urgPtr == '':
            raise MyPacketError('Не указан указатель на срочные данные.')
        #if options == '':
        #    raise MyPacketError('Не указаны опции.')
        #if data == '':
        #    raise MyPacketError('Не указаны данные.')

        try:
            packet = TCP(
                sport=int(srcPort),
                dport=int(dstPort),
                seq=int(seqNum),
                ack=int(ackNum),
                dataofs=offset,
                reserved=reserved,
                flags=flagsTCP,
                window=int(window),
                chksum=checksum,
                urgptr=int(urgPtr),
                options=None #[(op, v)]     #
            ) / data
        except:
            raise MyPacketError('Ошибка при создании пакета.')
            return None

        self.listPackets.append(packet)

        #print(packet)

        return packet

    def getInterfaces(self):
        return self.rawInterfaces

    def getType(self, packet):
        if packet.haslayer(ICMP):
            return 'ICMP'
        if packet.haslayer(IP):
            return 'IP'
        if packet.haslayer(TCP):
            return 'TCP'
        if packet.haslayer(UDP):
            return 'UDP'
        raise MyPacketError('Ошибка при получении типа пакета.')
        return None

    def getSrcAddr(self, packet):
        if packet.haslayer(IP):
            return packet.getlayer(IP).src
        else:
            print('No IP layer')
            return None

    def getDstAddr(self, packet):
        if packet.haslayer(IP):
            return packet.getlayer(IP).dst
        else:
            print('No IP layer')
            return None

    def getSrcPort(self, packet):
        if packet.haslayer(TCP):
            print(packet.getlayer(TCP).sport)
            return packet.getlayer(TCP).sport
        elif packet.haslayer(UDP):
            return packet.getlayer(UDP).sport
        else:
            print('No TCP or UDP layer')
            return None

    def getDstPort(self, packet):
        if packet.haslayer(TCP):
            print(packet.getlayer(TCP).dport)
            return packet.getlayer(TCP).dport
        elif packet.haslayer(UDP):
            return packet.getlayer(UDP).dport
        else:
            print('No TCP or UDP layer')
            return None

    def autoMAC(self, ipAddr):
        return get_mac_address(src=ipAddr)


    def sendAll(self, statusbar):
        try:
            if self.currentInterface.index == -1:
                print(self.currentInterface.index)
                print(self.currentInterface.interface)
                raise MyPacketError('Не выбран сетевой интерфейс.')
        except MyPacketError as e:
            statusbar.showMessage('Внимание! ' + e.message + ' Пакеты не отправлены. Выберите интерфейс: Инструменты -> Настройка интерфейсов')
            return

        for item in self.listPackets:
            print(self.currentInterface.index)
            print(self.currentInterface.interface)
            try:
                sendp(item, iface=self.currentInterface.interface, count=1)
                print("success")
            except:
                print("error")
                statusbar.showMessage('Внимание! Произошла ошибка при отправке.')
                continue
        self.listPackets.clear()
