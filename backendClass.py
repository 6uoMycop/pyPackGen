# This Python file uses the following encoding: utf-8
from tkinter import *
from tkinter.ttk import *
from scapy.layers.inet import IP, UDP, TCP, ICMP, IPOption
from scapy.layers.l2 import Ether
from scapy.data import load_ethertypes
from scapy.all import *
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
    def __init__(self, flag = False, ip = None, under = None, ether = None):
        self.layerIP = ip
        self.flagDataIP = flag # signalize if there is IP raw data so we can't add transport layer (otherwise everything will crash)
        self.etherType = ether

        if not self.flagDataIP:
            self.underLayer = under
        else:
            self.underLayer = None
    # ^^^ __init__ ^^^

    def construct(self):
        try:
            print('enter construct')
            if self.underLayer['packetType'] == 'TCP':
                print('    TCP')
                packetUnder = TCP(
                    sport=    self.underLayer['sport'],
                    dport=    self.underLayer['dport'],
                    seq=      self.underLayer['seq'],
                    ack=      self.underLayer['ack'],
                    dataofs=  self.underLayer['dataofs'],
                    reserved= self.underLayer['reserved'],
                    flags=    self.underLayer['flags'],
                    window=   self.underLayer['window'],
                    chksum=   self.underLayer['chksum'],
                    urgptr=   self.underLayer['urgptr'],
                    options=  self.underLayer['options']
                )
            elif self.underLayer['packetType'] == 'UDP':
                print('    UDP')
                packetUnder = UDP(
                    sport=  self.underLayer['sport'],
                    dport=  self.underLayer['dport'],
                    len=    self.underLayer['len'],
                    chksum= self.underLayer['chksum']
                )
            elif self.underLayer['packetType'] == 'ICMP':
                print('    ICMP')
                packetUnder = ICMP(
                    type=   self.underLayer['type'],
                    code=   self.underLayer['code'],
                    chksum= self.underLayer['chksum'],
                    id=     self.underLayer['id'],
                    seq=    self.underLayer['seq']
                )
            else:
                print('    None')
                packetUnder = None

            print(str(packetUnder))

            if self.layerIP != None:
                print('    IP')
                packetIP = IP(
                    version= self.layerIP['version'],
                    ihl=     self.layerIP['ihl'],
                    tos=     self.layerIP['tos'],
                    len=     self.layerIP['len'],
                    id=      self.layerIP['id'],
                    flags=   self.layerIP['flags'],
                    frag=    self.layerIP['frag'],
                    ttl=     self.layerIP['ttl'],
                    proto=   self.layerIP['proto'],
                    chksum=  self.layerIP['chksum'],
                    src=     self.layerIP['src'],
                    dst=     self.layerIP['dst'],
                    options= self.layerIP['options']
                )
                print(str(packetIP))

                print(self.layerIP['src'])
                print(self.layerIP['dst'])
                print(self.etherType)
                packetEther = Ether(
                    src=  get_mac_address(ip=self.layerIP['src']),
                    dst=  get_mac_address(ip=self.layerIP['dst']),
                    type= self.etherType
                )
            else:
                packetEther = Ether(
                    type=self.etherType
                )


            print('    Ether')
            print(str(packetEther))

        except:
            raise MyPacketError('Ошибка при конструировании пакета.')
            return None

        constructed = packetEther / packetIP / packetUnder
        return constructed


        #if self.layerIP == None:
        #    if self.underLayer == None:
        #        print('Empty packet')
        #        return None
        #    else:
        #        print('No IP header')
        #        if self.etherType == None:
        #            print('No EtherType')
        #        return self.underLayer
        #else:
        #    print(str(self.underLayer))
        #    if self.underLayer == None:
        #        print('No transport layer')
        #        if self.etherType == None:
        #            print('No EtherType')
        #        return self.layerIP
        #    else:
        #        return self.layerIP / self.underLayer

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

    def createTCP(
        self,
        srcPort,
        dstPort,
        seqNum,
        ackNum,
        offset,
        reserved,
        urg,
        ack,
        psh,
        rst,
        syn,
        fin,
        window,
        checksum,
        urgPtr,
        options,
        data,
        index=None
    ):
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

        N_options = []
        for item in options:
            if item[0] == 'EOL' or item[0] == 'NOP' or item[0] == 'SAckOK' or item[0] == 'AltChkSumOpt':
                N_options.append( (item[0], None) )
            elif item[0] == 'MSS' or item[0] == 'UTO' or item[0] == 'WScale':
                N_options.append( (item[0], int(item[1])) )
            elif item[0] == 'Mood':
                N_options.append( (item[0], item[1]) )
            elif item[0] == 'SAck' or item[0] == 'Timestamp' or item[0] == 'AltChkSum' or item[0] == 'TFO':
                N_options.append( (item[0], (int(item[1]),int(item[2])) ) )

        N_flagsTCP = 0;
        N_flagsTCP += 0b00100000 if urg else 0
        N_flagsTCP += 0b00010000 if ack else 0
        N_flagsTCP += 0b00001000 if psh else 0
        N_flagsTCP += 0b00000100 if rst else 0
        N_flagsTCP += 0b00000010 if syn else 0
        N_flagsTCP += 0b00000001 if fin else 0

        print("flags:    " + str(bin(N_flagsTCP)))
        try:
            # check if input is valid
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

            #if options == '':
            #    N_options = []
            #else:
            #    N_options = int(options, 16) ### AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

            #packet = TCP(
            #    sport=    int(srcPort),
            #    dport=    int(dstPort),
            #    seq=      int(seqNum),
            #    ack=      int(ackNum),
            #    dataofs=  N_offset,
            #    reserved= N_reserved,
            #    flags=    N_flagsTCP,
            #    window=   int(window),
            #    chksum=   N_checksum,
            #    urgptr=   N_urgPtr,
            #    options=  N_options)

            packet = dict(
                sport=      int(srcPort),
                dport=      int(dstPort),
                seq=        int(seqNum),
                ack=        int(ackNum),
                dataofs=    N_offset,
                reserved=   N_reserved,
                flags=      N_flagsTCP,
                window=     int(window),
                chksum=     N_checksum,
                urgptr=     N_urgPtr,
                options=    N_options,
                packetType= 'TCP',
                data=       data if data != '' else None)
            #if data != '':
            #    packet = packet / data
        except:
            raise MyPacketError('Ошибка при создании пакета.')
            return None

        #add to list
        if index == None or index >= len(self.listPackets):
            self.listPackets.append(packetClass(under=packet))
        elif not self.listPackets[index].flagDataIP:
            self.listPackets[index].underLayer = packet

        return packet
    # ^^^ createTCP ^^^

    def createUDP(
        self,
        srcPort,
        dstPort,
        datagramLength,
        checksum,
        data,
        index=None
    ):
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
            #packet = UDP(
            #    sport=  int(srcPort),
            #    dport=  int(dstPort),
            #    len=    N_datagramLength,
            #    chksum= N_checksum)
            packet = dict(
                sport=      int(srcPort),
                dport=      int(dstPort),
                len=        N_datagramLength,
                chksum=     N_checksum,
                packetType= 'UDP',
                data=       data if data != '' else None)
            #if data != '':
            #    packet = packet / data
        except:
            raise MyPacketError('Ошибка при создании пакета.')
            return None

        #add to list
        print(str(index))
        if index == None or index >= len(self.listPackets):
            self.listPackets.append(packetClass(under=packet))
        elif not self.listPackets[index].flagDataIP:
            self.listPackets[index].underLayer = packet

        return packet
    # ^^^ createUDP ^^^

    def createICMP(
        self,
        type,
        code,
        checksum,
        identifier,
        seq,
        data,
        index=None
    ):
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
            #packet = ICMP(
            #    type=   int(type),
            #    code=   int(code),
            #    chksum= N_checksum,
            #    id=     int(identifier),
            #    seq=    int(seq))
            packet = dict(
                type=       int(type),
                code=       int(code),
                chksum=     N_checksum,
                id=         int(identifier),
                seq=        int(seq),
                packetType= 'ICMP',
                data=       data if data != '' else None)
            #if data != '':
            #    packet = packet / data

            print(
                'ICMP(type=' + str(type)       +
                ',code='     + str(code)       +
                ',chksum='   + str(N_checksum) +
                ',id='       + str(identifier) +
                ',seq='      + str(seq)        + ')' +
                ' / data')
        except:
            raise MyPacketError('Ошибка при создании пакета.')
            return None

        #add to list
        if index == None or index >= len(self.listPackets):
            self.listPackets.append(packetClass(under=packet))
        elif not self.listPackets[index].flagDataIP:
            self.listPackets[index].underLayer = packet

        return packet
    # ^^^ createICMP

    def createIP(
        self,
        version,
        IHL,
        DSCP,
        length,
        ID,
        reservedFlag,
        dontFragmentFlag,
        moreFragmentsFlag,
        fragmentOffset,
        TTL,
        protocol,
        checksum,
        srcAddr,
        dstAddr,
        options,
        data,
        index=None
    ):
        try:
            # check if input is valid
            if version == '':
                raise MyPacketError('Не указана версия протокола IP.')
            if DSCP == '':
                raise MyPacketError('Не указан тип сервиса.')
            if ID == '':
                raise MyPacketError('Не указан ID.')
            if TTL == '':
                raise MyPacketError('Не указано время жизни.')
            if srcAddr == '':
                raise MyPacketError('Не указан IP-адрес отправки.')
            if dstAddr == '':
                raise MyPacketError('Не указан IP-адрес назначения.')

            # prepare
            if checksum == '':
                N_checksum = None
            else:
                N_checksum = int(checksum, 16)

            N_flags = 0
            N_flags += 0b100 if reservedFlag      else 0
            N_flags += 0b010 if dontFragmentFlag  else 0
            N_flags += 0b001 if moreFragmentsFlag else 0

            if IHL == '':
                N_IHL = None
            else:
                N_IHL = int(IHL)

            if length == '':
                N_length = None
            else:
                N_length = int(length)

            if fragmentOffset == '':
                N_fragmentOffset = 0
            else:
                N_fragmentOffset = int(fragmentOffset)

            print("ver:      " + str(version))
            print("ihl:      " + str(N_IHL))
            print("tos:      " + str(DSCP))
            print("len:      " + str(N_length))
            print("id:       " + str(ID))
            print("flags:    " + str(N_flags))
            print("offset:   " + str(N_fragmentOffset))
            print("ttl:      " + str(TTL))
            print("protocol: " + str(protocol))
            print("checksum: " + str(N_checksum))
            print("src:      " + str(srcAddr))
            print("dst:      " + str(dstAddr))


            #construct packet
            #packet = IP(
            #    version= int(version),
            #    ihl=     N_IHL,
            #    tos=     int(DSCP),
            #    len=     N_length,
            #    id=      int(ID),
            #    flags=   N_flags,
            #    frag=    N_fragmentOffset,
            #    ttl=     int(TTL),
            #    proto=   protocol,
            #    chksum=  N_checksum,
            #    src=     srcAddr,
            #    dst=     dstAddr,
            #    options= IPOption(options)
            #)

            packet = dict(
                version=    int(version),
                ihl=        N_IHL,
                tos=        int(DSCP),
                len=        N_length,
                id=         int(ID),
                flags=      N_flags,
                frag=       N_fragmentOffset,
                ttl=        int(TTL),
                proto=      protocol,
                chksum=     N_checksum,
                src=        srcAddr,
                dst=        dstAddr,
                options=    IPOption(options),
                #packetType= 'IP',
                data=       Raw(load=data) if data != '' else None)

            #if data != '':
            #    packet = packet / Raw(load=data)

            print(
                'IP(version='        + str(version         ) +
                ',ihl='              + str(N_IHL           ) +
                ',tos='              + str(DSCP            ) +
                ',len='              + str(N_length        ) +
                ',id='               + str(ID              ) +
                ',flags='            + str(N_flags         ) +
                ',frag='             + str(N_fragmentOffset) +
                ',ttl='              + str(TTL             ) +
                ',proto='            + str(protocol        ) +
                ',chksum='           + str(N_checksum      ) +
                ',src='              + str(srcAddr         ) +
                ',dst='              + str(dstAddr         ) +
                ',options=IPOption(' + str(options         ) + ')' +
                ' / raw(load=data)')

        except MyPacketError as e:
            raise MyPacketError('Ошибка при создании пакета.')
            return None

        #add to list
        print(str(index))
        if index == None or index >= len(self.listPackets):
            self.listPackets.append(packetClass(flag= True if data != '' else False, ip=packet))
        else:
            self.listPackets[index].layerIP = packet
            if(data != ''):
                self.listPackets[index].underLayer = None

        return packet
    # ^^^ createIP ^^^

    def createEthernet(self, etherType, index = None):
        if etherType == '':
            N_etherType = 0x0800
        else:
            N_etherType = int(etherType, 16)

        print('--->    EtherType: ' + str(N_etherType))

        #add to list
        print(str(index))
        if index == None or index >= len(self.listPackets):
            self.listPackets.append(packetClass(ether=N_etherType))
        else:
            self.listPackets[index].etherType=N_etherType



        return packet

    # ^^^ createEthernet ^^^


    def getInterfaces(self):
        return self.rawInterfaces
    # ^^^ getInterfaces ^^^

    def getType(self, packet):
        if packet != None:
            if packet.underLayer != None:
                return packet.underLayer['packetType']
            if packet.layerIP != None:
                return 'IP'
        return None
    # ^^^ getType ^^^

    def getSrcAddr(self, packet):
        if packet != None:
            if packet.layerIP != None:
                return packet.layerIP['src']
            else:
                print('No IP layer')
        return None
    # ^^^ getSrcAddr ^^^

    def getDstAddr(self, packet):
        if packet != None:
            if packet.layerIP != None:
                return packet.layerIP['dst']
            else:
                print('No IP layer')
        return None
    # ^^^ getDstAddr ^^^

    def getSrcPort(self, packet):
        if packet != None:
            if packet.underLayer != None:
                if packet.underLayer['packetType'] == 'TCP' or packet.underLayer['packetType'] == 'UDP':
                    return packet.underLayer['sport']
                else:
                    print('No TCP or UDP layer')
        return None
    # ^^^ getSrcPort ^^^

    def getDstPort(self, packet):
        if packet != None:
            if packet.underLayer != None:
                if packet.underLayer['packetType'] == 'TCP' or packet.underLayer['packetType'] == 'UDP':
                    return packet.underLayer['dport']
                else:
                    print('No TCP or UDP layer')
        return None
    # ^^^ getDstPort ^^^

    def getEtherType(self, packet):
        if packet != None:
            return packet.etherType
        return None
    # ^^^ getEtherType ^^^

    def sendAll(self, statusbar, delete):
        try:
            if self.currentInterface.index == -1:
                print(self.currentInterface.index)
                print(self.currentInterface.interface)
                raise MyPacketError('Не выбран сетевой интерфейс. Выберите интерфейс: Инструменты -> Настройка интерфейсов')
        except MyPacketError as e:
            statusbar.showMessage('Внимание! Пакеты не отправлены. ' + e.message)
            return -1

        for item in self.listPackets:
            #toSend = Ether(src=self.autoMAC(item.layerIP.src), dst=self.autoMAC(item.layerIP.dst), type=item.etherType) / item.construct()

            #print(
            #    'Ether(src=' + str(self.autoMAC(item.layerIP.src)) +
            #    ',dst='      + str(self.autoMAC(item.layerIP.dst)) +
            #    ',type='     + str(item.etherType                ) + ')')

            interfaceName = self.currentInterface.interface.get('name')
            print('ifname: ' + interfaceName)
            #print('packet: ' + str(ls(toSend)))
            #print(str(toSend))
            errCntr = 0
            try:
                toSend = item.construct()
                sendp(toSend, iface=interfaceName, count=1)
                print("success")
            except:
                print("error")
                statusbar.showMessage('Внимание! Произошла ошибка при отправке.')
                errCntr += 1
                continue
        lenList = len(self.listPackets)
        statusbar.showMessage('Отправлено ' + str(lenList-errCntr) + ' из ' + str(lenList) + ' пакетов.')
        if delete:
            self.listPackets.clear()
        return 0
    # ^^^ sendAll ^^^

# ^^^ class backendClass ^^^
