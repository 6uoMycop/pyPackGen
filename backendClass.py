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
    def __init__(self, msg):
        self.message = msg
    # ^^^ __init__ ^^^
# ^^^ class MyPacketError ^^^

class interfaceClass:
    def __init__(self):
        self.index = -1
        self.interface = None
    # ^^^ __init__ ^^^
# ^^^ class interfaceClass ^^^

class packetClass:
    def __init__(self, ip = None, under = None):
        self.layerIP = ip
        self.underLayer = under
    # ^^^ __init__ ^^^

    def construct(self):
        if layerIP == None:
            if(underLayer == None):
                print('Empty packet')
            else:
                print('No IP header')
            return None
        return layerIP / underLayer;
    # ^^^ construct ^^^
# ^^^ class packetClass ^^^

class backendClass:
    def __init__(self):
        self.listPackets = list()
        self.currentInterface = interfaceClass()
        self.rawInterfaces = get_windows_if_list()
    # ^^^ __init__ ^^^

    def getNumberOfPackets(self):
        return len(self.listPackets)
    # ^^^ getNumberOfPackets ^^^

    def createTCP(self, srcPort, dstPort, seqNum, ackNum, offset, reserved, urg, ack, psh, rst, syn, fin, window, checksum, urgPtr, options, data, index=None):
        print("src:      " + str(srcPort))
        print("dst:      " + str(dstPort))
        print("seq:      " + str(seqNum))
        print("ack:      " + str(ackNum))
        print("offset:   " + str(offset))
        print("reserved: " + str(reserved))
        print("urg:      " + str(urg))
        print("ack:      " + str(ack))
        print("psh:      " + str(psh))
        print("rst:      " + str(rst))
        print("syn:      " + str(syn))
        print("fin:      " + str(fin))
        print("window:   " + str(window))
        print("checksum: " + str(checksum))
        print("urg ptr:  " + str(urgPtr))
        print("options:  " + str(options))
        print("data:     " + str(data))

        N_flagsTCP = 0;
        N_flagsTCP += 0b00000001 if urg else 0
        N_flagsTCP += 0b00000010 if ack else 0
        N_flagsTCP += 0b00000100 if psh else 0
        N_flagsTCP += 0b00001000 if rst else 0
        N_flagsTCP += 0b00010000 if syn else 0
        N_flagsTCP += 0b00100000 if fin else 0

        print("flags:    " + str(bin(N_flagsTCP)))

        # check if input is valid
        if srcPort == '':
            raise MyPacketError('Не указан порт отправки.')
            return None
        if dstPort == '':
            raise MyPacketError('Не указан порт назначения.')
            return None
        if seqNum == '':
            raise MyPacketError('Не указан SEQ.')
            return None
        if ackNum == '':
            raise MyPacketError('Не указан ACK.')
            return None
        if offset == '':
            raise MyPacketError('Не указано смещение данных.')
            return None
        if reserved == '':
            raise MyPacketError('Не указано значение зарезервированного поля.')
            return None
        if window == '':
            raise MyPacketError('Не указан размер окна.')
            return None
        if checksum == '':
            raise MyPacketError('Не указана контрольная сумма.')
            return None
        if urgPtr == '':
            raise MyPacketError('Не указан указатель на срочные данные.')
            return None


        # prepare
        if offset == None:
            N_offset = None
        else:
            N_offset = int(offset, 16)

        N_reserved = int(reserved, 2)

        if checksum == None:
            N_checksum = None
        else:
            N_checksum = int(checksum, 16)

        N_urgPtr = int(urgPtr, 16)

        if options == '':
            N_options = 0
        else:
            N_options = int(options, 16)

        try:
            packet = TCP(
                sport=    int(srcPort),
                dport=    int(dstPort),
                seq=      int(seqNum),
                ack=      int(ackNum),
                dataofs=  N_offset,
                reserved= N_reserved,
                flags=    N_flagsTCP,
                window=   int(window),
                chksum=   N_checksum,
                urgptr=   N_urgPtr,
                options=  N_options
            ) / data
        except:
            raise MyPacketError('Ошибка при создании пакета.')
            return None

        #add to list
        if index == None:
            self.listPackets.append(packetClass(under=packet))
        else:
            self.listPackets[index].underLayer = packet

        return packet
    # ^^^ createTCP ^^^

    def createUDP(self, srcPort, dstPort, datagramLength, checksum, data, index=None):
        print("src:      " + str(srcPort))
        print("dst:      " + str(dstPort))
        print("len:      " + str(datagramLength))
        print("checksum: " + str(checksum))
        print("data:     " + str(data))

        try:
            # check if input is valid
            if srcPort == '':
                raise MyPacketError('Не указан порт отправки.')
            if dstPort == '':
                raise MyPacketError('Не указан порт назначения.')

            # prepare
            if datagramLength == '':
                N_datagramLength = None
            else:
                N_datagramLength = int(datagramLength)

            if checksum == '':
                N_checksum = None
            else:
                N_checksum = int(checksum, 16)

            #construct packet
            packet = UDP(
                sport=  int(srcPort),
                dport=  int(dstPort),
                len=    N_datagramLength,
                chksum= N_checksum,
            ) / data
        except:
            raise MyPacketError('Ошибка при создании пакета.')
            return None

        #add to list
        if index == None:
            self.listPackets.append(packetClass(under=packet))
        else:
            self.listPackets[index].underLayer = packet

        return packet
    # ^^^ createUDP ^^^

    def createICMP(self, type, code, checksum, identifier, seq, data, index=None):
        print("type:       " + str(type))
        print("code:       " + str(code))
        print("checksum:   " + str(checksum))
        print("identifier: " + str(identifier))
        print("seq:        " + str(seq))
        print("data:       " + str(data))

        try:
            # check if input is valid
            if code == '':
                raise MyPacketError('Не указан код.')
            if identifier == '':
                raise MyPacketError('Не указан идентификатор.')
            if seq == '':
                raise MyPacketError('Не указан номер последовательности.')

            # prepare
            if checksum == '':
                N_checksum = None
            else:
                N_checksum = int(checksum, 16)

            #construct packet
            packet = ICMP(
                type=   int(type),
                code=   int(code),
                chksum= N_checksum,
                id=     int(identifier),
                seq=    int(seq)
            ) / data
        except:
            raise MyPacketError('Ошибка при создании пакета.')
            return None

        #add to list
        if index == None:
            self.listPackets.append(packetClass(under=packet))
        else:
            self.listPackets[index].underLayer = packet

        return packet
    # ^^^ createICMP

    #def addIP(self):
    #    packet = IP (
    #        version=int(ver),
    #        ihl=ihl,
    #        tos=tos,
    #        len=length,
    #        id=int(id),
    #        flags=flags,
    #        frag=int(fo),
    #        ttl=int(ttl),
    #        proto=pr,
    #        chksum=chk,
    #        src=src,
    #        dst=dst,
    #        options=[IPOption(copy_flag=var_f.get(), optclass=var_cd.get(), option=combo[3].get(), length=int(l), value=v)]
    #    ) / packet

    def getInterfaces(self):
        return self.rawInterfaces
    # ^^^ getInterfaces ^^^

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
    # ^^^ getType ^^^

    def getSrcAddr(self, packet):
        if packet.haslayer(IP):
            return packet.getlayer(IP).src
        else:
            print('No IP layer')
            return None
    # ^^^ getSrcAddr ^^^

    def getDstAddr(self, packet):
        if packet.haslayer(IP):
            return packet.getlayer(IP).dst
        else:
            print('No IP layer')
            return None
    # ^^^ getDstAddr ^^^

    def getSrcPort(self, packet):
        if packet.haslayer(TCP):
            print(packet.getlayer(TCP).sport)
            return packet.getlayer(TCP).sport
        elif packet.haslayer(UDP):
            return packet.getlayer(UDP).sport
        else:
            print('No TCP or UDP layer')
            return None
    # ^^^ getSrcPort ^^^

    def getDstPort(self, packet):
        if packet.haslayer(TCP):
            print(packet.getlayer(TCP).dport)
            return packet.getlayer(TCP).dport
        elif packet.haslayer(UDP):
            return packet.getlayer(UDP).dport
        else:
            print('No TCP or UDP layer')
            return None
    # ^^^ getDstPort ^^^

    def autoMAC(self, ipAddr):
        return get_mac_address(src=ipAddr)
    # ^^^ autoMAC ^^^


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
                sendp(item.construct(), iface=self.currentInterface.interface, count=1)
                print("success")
            except:
                print("error")
                statusbar.showMessage('Внимание! Произошла ошибка при отправке.')
                continue
        self.listPackets.clear()
    # ^^^ sendAll ^^^

# ^^^ class backendClass ^^^
