import socket
import struct
from dataclasses import dataclass
from typing import Tuple

recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
recv_sock.bind(("127.0.0.1", 20000))
fuzz_addr = 0

MESSAGE_CLASS_VALUES = [
   0x0000,
   0x0001,
   0x0002,
   0x00ff,
   0x4000,
   0x8000,
   0x8001,
   0x8002,
   0x8003,
   0x8004,
   0x8005,
   0x8006,
   0x8007,
   0x8009,
   0x800A,
   0x800B,
   0xC000,
   0xC001,
   0xC002,
   0xC004
]

@dataclass
class BaseHeader:
    Reserved:bytes        # BYTE
    Flags:bytes            # WORD
    TimeToReachQueue: bytes # DWORD
    PacketSize: int = 0      # DWORD
    VersionNumber: int = 0x10   # BYTE
    Signature: int = 0x524F494C      # DWORD

    def pack(self) -> bytes:
        # '<' little-endian, B B H I I I
        return struct.pack('<B1s2sII4s',
                           self.VersionNumber,
                           self.Reserved,
                           self.Flags,
                           self.Signature,
                           self.PacketSize,
                           self.TimeToReachQueue)

@dataclass
class InternalHeader:
    Flags: bytes    # WORD
    Reserved: int = 0 # WORD

    def pack(self) -> bytes:
        return struct.pack('<H2s', self.Reserved, self.Flags)
    
@dataclass
class ConnectionParametersHeader:
    RecoverableAckTimeout: int  # DWORD
    AckTimeout: int     # DWORD
    WindowSize: int # WORD
    Reserved: int = 0    # WORD

    def pack(self) -> bytes:
        fmt = '<4s4sH2s'
        return struct.pack(fmt,
                           self.RecoverableAckTimeout,
                           self.AckTimeout,
                           self.Reserved,
                           self.WindowSize)
    
@dataclass
class EstablishConnectionHeader:
    TimeStamp: bytes     # DWORD
    ClientGuid:bytes
    ServerGuid:bytes
    OperatingSystem: bytes  # WORD
    ClientGuid:bytes
    ServerGuid:bytes
    Reserved: int = 0     # WORD
    Padding: bytes = b'\x5a' * 512    # 512 bytes

    def pack(self) -> bytes:
        fmt = '<16s16s4s2sH512s'
        return struct.pack(fmt,
                           self.ClientGuid,
                           self.ServerGuid,
                           self.TimeStamp,
                           self.OperatingSystem,
                           self.Reserved,
                           self.Padding)
    
@dataclass   
class MessagePropertiesHeader:
    Flags:bytes              # byte
    LabelLength: int        # byte
    MessageClass:int        # WORD
    CorrelationID:bytes     # 20 byte
    BodyType:bytes            # DWORD
    ApplicationTag:bytes      # DWORD
    MessageSize:int         # DWORD
    AllocationBodySize:int  # DWORD
    PrivacyLevel:int        # DWORD
    HashAlgorithm:int       # DWORD
    EncryptionAlgorithm:int # DWORD
    ExtensionSize:int       # DWORD
    Label:bytes
    ExtensionData:bytes
    MessageBody:bytes

    def pack(self) -> bytes:
        fmt = '<1sBH20s4s4sIIIIII'
        return struct.pack(fmt,
                           self.Flags,
                           self.LabelLength,
                           self.MessageClass,
                           self.CorrelationID,
                           self.BodyType, self.ApplicationTag, self.MessageSize, self.AllocationBodySize, self.PrivacyLevel, self.HashAlgorithm, self.EncryptionAlgorithm, self.ExtensionSize) + self.Label + self.ExtensionData + self.MessageBody

@dataclass
class DebugHeader:
    Flags:bytes               # WORD
    QueueIdentifier:bytes   # 16 byte
    Reserved:int = 0          # WORD

    def pack(self) -> bytes:
        fmt = '<2sH'
        return struct.pack(fmt,
                           self.Flags,
                           self.Reserved) + self.QueueIdentifier
@dataclass
class UserHeader:
    SourceQueueManager:bytes
    QueueManagerAddress:bytes            # WORD
    TimeToBeReceived:bytes                 # DWORD
    SentTime:bytes                         # DWORD
    MessageID:bytes
    Flags:bytes
    DestinationQueue:bytes 
    AdminQueue:bytes 
    ResponseQueue:bytes 
    ConnectorType:bytes

    def pack(self) -> bytes:
        fmt = '<16s16s4s4s4s4s'
        data = struct.pack(fmt,
                           self.SourceQueueManager,
                           self.QueueManagerAddress,
                           self.TimeToBeReceived,
                           self.SentTime,
                           self.MessageID,
                           self.Flags
                           )
        
        data += self.DestinationQueue + self.AdminQueue + self.ResponseQueue + self.ConnectorType
        return data
       

@dataclass
class TransactionHeader:
    Flags:bytes
    TxSequenceID:bytes
    TxSequenceNumber:int
    PreviousTxSequenceNumber:int 
    ConnectorQMGuid:bytes

    def pack(self) -> bytes:
        fmt = '<4s8sII'
        
        return struct.pack(fmt,
                           self.Flags,
                           self.TxSequenceID,
                           self.TxSequenceNumber,
                           self.PreviousTxSequenceNumber) + self.ConnectorQMGuid

@dataclass
class SecurityHeader:
    Flags:bytes                   # WORD
    SenderIdSize:bytes          # WORD
    EncryptionKeySize:int       # WORD
    SignatureSize:int           # WORD
    SenderCertSize:int
    ProviderInfoSize:int
    SecurityID:bytes

    def pack(self) -> bytes:
        fmt = '<2s2sHHII'
        return struct.pack(fmt,
                           self.Flags,
                           self.SenderIdSize,
                           self.EncryptionKeySize,
                           self.SignatureSize,
                           self.SenderCertSize,
                           self.ProviderInfoSize) + self.SecurityID


@dataclass
class MQFAddressHeader:
    HeaderSize:int
    HeaderID:int
    ElementCount:int
    FormatNameList:bytes
    Reserved:int = 0

    def pack(self) -> bytes:
        fmt = '<IHHI'
        return struct.pack(fmt,
                           self.HeaderSize,
                           self.HeaderID,
                           self.Reserved,
                           self.ElementCount) + self.FormatNameList

@dataclass
class SoapHeader:
    HeaderDataLength:int
    Header:bytes
    BodyDataLength:int
    Body :bytes
    Reserved:int = 0
    Reserved1:int = 0
    BodySectionID:int = 0x0384
    HeaderSectionID:int = 0x0320

    def pack(self) -> bytes:
        fmt = '<HHI'
        fmt1 = '<HHI'
        return  struct.pack(fmt,
                            self.HeaderSectionID,
                            self.Reserved,
                            self.HeaderDataLength) + self.Header + \
                struct.pack(fmt1,
                            self.BodySectionID,
                            self.Reserved1,
                            self.BodyDataLength) + self.Body
    
@dataclass
class SRMPEnvelopeHeader:
    HeaderId:bytes
    DataLength:int
    Data:bytes
    Reserved:int = 0

@dataclass
class MQFSignatureHeader:
    data:bytes
    size:int
    ID:int = 0x015E
    Reserved:int = 0

    def pack(self) -> bytes:
        fmt = '<HHI'
        return struct.pack(fmt,
                           self.ID,
                           self.Reserved,
                           self.size) + self.data


class Packet:
    def __init__(self, fuzz_data, len):
        self.fuzz_data = fuzz_data
        self.len = len
        self.index = 0
        
    def _GetSize(self, size) -> bytes:
        if (self.index + size) > self.len:
            return None
        
        data = self.fuzz_data[self.index : self.index + size]
        self.index += size
        return data
    
    # def _GetData(self, size) -> bytes:
    #     if (self.dataIndex + size) > self.dataLen:
    #         return None
        
    #     data = self.data[self.dataIndex : self.dataIndex + size]
    #     self.dataIndex += size
    #     return data

    
    def GetPacket(self):
        establishConnectionPack = self._GetEstablishPacket()

        connectionParameterPack = self._GetConnectionParameterPacket()
        userMessage = self._GetUserMessage()
        return [establishConnectionPack, connectionParameterPack, userMessage]


    def _GetEstablishPacket(self):
        baseHeader = self._GetBaseHeader()
        internalHeader = self._GetInternalHeader()
        flags = internalHeader.Flags
        internalHeader.Flags = self._SetBits(flags[0], 0, 4, 2) + flags[1:]
        internalHeader_pack = internalHeader.pack()
        establishConnectionHeader = self._GetEstablishConnectionHeader()
        establishConnectionHeader_pack = establishConnectionHeader.pack()
        baseHeader.PacketSize = len(internalHeader_pack) + len(establishConnectionHeader_pack) + 16
        establishConnection_pack = baseHeader.pack() + internalHeader_pack + establishConnectionHeader_pack
        
        return establishConnection_pack

    def _GetConnectionParameterPacket(self):
        baseHeader = self._GetBaseHeader()
        internalHeader = self._GetInternalHeader()
        flags = internalHeader.Flags
        internalHeader.Flags = self._SetBits(flags[0], 0, 4, 3) + flags[1:]
        internalHeader_pack = internalHeader.pack()

        connectionParametersHeader = self._GetConnectionParametersHeader()

        connectionParametersHeader_pack = connectionParametersHeader.pack()
        baseHeader.PacketSize = len(internalHeader_pack) + len(connectionParametersHeader_pack) + 16

        connection_pack = baseHeader.pack() + internalHeader_pack + connectionParametersHeader_pack

        return connection_pack

    def _GetUserMessage(self):
        baseHeader = self._GetBaseHeader()
        baseFlags = baseHeader.Flags
        baseFlags = self._SetBits(baseFlags[0], 3, 3, 0) +  baseFlags[1:]
        baseHeader.Flags = baseFlags
        userHeader = self._GetUserHeader()
        userFlags = userHeader.Flags
        
        transactionHeader = None
        # 是否有transaction header
        if self._GetBits(userFlags[2], 4, 4) == 1:
            transactionHeader = self._GetTransactionHeader()
        else:
            self._GetSize(16)
            transactionHeader = b''

        if self._GetBits(userFlags[2], 3, 3) == 1:
            securityHeader = self._GetSecurityHeader()
        else:
            securityHeader = b''

        if self._GetBits(userFlags[2], 5, 5) == 1:
            messagePropertiesHeader = self._GetMessagePropertiesHeader()
        else:
            self._GetSize(28)
            messagePropertiesHeader = b''

        # baseFlags = self._SetBits(baseFlags[0], 5, 5, 1) +  baseFlags[1:]
        if self._GetBits(baseFlags[0], 5, 5) :
            debugHeader = self._GetDebugHeader()
        else:
            self._GetSize(18)
            debugHeader = b''

        if self._GetBits(userFlags[3], 4, 4) :
            soapHeader = self._GetSoapHeader()
        else:
            self._GetSize(8)
            soapHeader = b''
        
        if self._GetBits(userFlags[2], 7, 7) :
            multiQueueFormatHeaderPack = self._GetMultiQueueFormatHeader()
        else:
            self._GetSize(16)
            multiQueueFormatHeaderPack = b''

        # TODO 目前不通过HTTP,不设置J - AH 
        
        baseHeader.PacketSize = len(userHeader.pack()) + len(transactionHeader) + len(securityHeader) + len(messagePropertiesHeader) + len(debugHeader) + len(multiQueueFormatHeaderPack) + len(soapHeader) + 16
        return baseHeader.pack() + userHeader.pack() + transactionHeader + securityHeader + messagePropertiesHeader + debugHeader + multiQueueFormatHeaderPack + soapHeader

    def _GetUserHeader(self):
        SourceQueueManager = b'\xD1\x58\x73\x55\x50\x91\x95\x95\x49\x97\xB6\xE6\x11\xEA\x26\xC6'
        QueueManagerAddress = b'\x00' * 16
        TimeToBeReceived = self._GetSize(4)
        SentTime = self._GetSize(4)
        MessageID = self._GetSize(4)
        Flags = self._GetSize(4)

        DM = self._GetBits(Flags[0], 5, 6)
        if DM > 1:
            Flags = self._SetBits(Flags[0], 5, 6, 0) + Flags[1:]

        # Flags = Flags[:1] + self._SetBits(Flags[1], 2, 4, 3) + Flags[2:]
        # Flags = Flags[:1] + self._SetBits(Flags[1], 5, 7, 6) + Flags[2:]
        # Flags = Flags[:1] + self._SetBits(Flags[2], 0, 2, 7) + Flags[2:]
        # print(Flags)
        #userHeader = UserHeader(SourceQueueManager=SourceQueueManager, QueueManagerAddress=QueueManagerAddress, TimeToBeReceived=TimeToBeReceived, SentTime=SentTime, MessageID=MessageID, Flags=Flags)
        DestinationQueue = self._GetDestinationQueue(Flags)
        AdminQueue = self._GetAdminQueue(Flags)
        ResponseQueue = self._GetResponseQueue(Flags)
        # print(DestinationQueue, AdminQueue, ResponseQueue)
        ConnectorType = self._GetSize(16)
        if self._GetBits(Flags[2], 6, 6) == 0:
            ConnectorType = b''

        userHeader = UserHeader(SourceQueueManager=SourceQueueManager, QueueManagerAddress=QueueManagerAddress, TimeToBeReceived=TimeToBeReceived, SentTime=SentTime, MessageID=MessageID, Flags=Flags, DestinationQueue=DestinationQueue, AdminQueue=AdminQueue, ResponseQueue=ResponseQueue, ConnectorType=ConnectorType)

        return userHeader
    
    def _GetSecurityHeader(self):
        # Flags = self._GetSize(2)
        Flags = b'\x01\x00'
        SenderIdSize = b'\x1C\x00'
        # EncryptionKeySize = int.from_bytes(self._GetSize(2), 'little')
        # SignatureSize = int.from_bytes(self._GetSize(2), 'little')
        # SenderCertSize = int.from_bytes(self._GetSize(4), 'little')
        # ProviderInfoSize = int.from_bytes(self._GetSize(4), 'little')
        EncryptionKeySize = 0
        SignatureSize = 0
        SenderCertSize = 0
        ProviderInfoSize = 0

        # SecurityID类型
        ST = self._GetBits(Flags[0], 0, 3)
        if ST == 0:
            SenderIdSize = 0
            SecurityID = b''
        elif ST == 2:
            SenderIdSize = 16
            SecurityID = b'\x00' * 16
        else:
            SecurityID = b'\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xAD\x4A\x9E\xBD\x36\xD9\xFA\x3D\x63\xA6\x56\xDA\xE8\x03\x00\x00'
    
        # 是否加密
        # EB = self._GetBits(Flags[0], 4, 4)
        # if EB:
        #     pass
        
        # signature type
        # self._SetBits(Flags[1], 0, 8, 0)

        securityHeader = SecurityHeader(Flags=Flags, SenderIdSize=SenderIdSize, EncryptionKeySize=EncryptionKeySize, SignatureSize=SignatureSize, SenderCertSize=SenderCertSize, ProviderInfoSize=ProviderInfoSize, SecurityID=SecurityID)
        return securityHeader.pack()

    def _GetTransactionHeader(self):
        Flags = self._GetSize(4)
        TxSequenceID = self._GetSize(8)
        TxSequenceNumber = int.from_bytes(self._GetSize(4), 'little')
        PreviousTxSequenceNumber = 0
        ConnectorQMGuid = b''
     
        # 是否是第一个消息
        FM = self._GetBits(Flags[0], 2, 2)
       
        if FM:
            TxSequenceNumber = 1
            PreviousTxSequenceNumber = 0
        else:
            if TxSequenceNumber > 1:
                PreviousTxSequenceNumber = TxSequenceNumber - 1
            else:
                TxSequenceNumber = 2
                PreviousTxSequenceNumber = 1

        # 是否有connectorQMGuid
        CG = self._GetBits(Flags[0], 0, 0)
        if CG:
            ConnectorQMGuid = b'\xC6\x26\xEA\x11\xE6\xB6\x97\x49\x95\x95\x91\x50\x55\x73\x58\xD1'
        
        return TransactionHeader(Flags=Flags, TxSequenceID=TxSequenceID, TxSequenceNumber=TxSequenceNumber, PreviousTxSequenceNumber=PreviousTxSequenceNumber, ConnectorQMGuid=ConnectorQMGuid).pack()
   
    def _GetMessagePropertiesHeader(self):
        Flags = self._GetSize(1)              # byte
        LabelLength = int.from_bytes(self._GetSize(1), 'little')        # byte
        MessageClass = int.from_bytes(self._GetSize(2), 'little')       # WORD
        CorrelationID = b'\x00' * 20     # 20 byte
        # TODO 根据BodyType 设置消息体类型
        BodyType = b'\x08\x00\x00\x00'            # DWORD
        ApplicationTag = self._GetSize(4)      # DWORD
        MessageSize = int.from_bytes(self._GetSize(4), 'little')         # DWORD
        AllocationBodySize = int.from_bytes(self._GetSize(4), 'little')  # DWORD
        # TODO 根据PrivacyLevel 设置加密类型
        PrivacyLevel = 0        # DWORD
        HashAlgorithm = int.from_bytes(self._GetSize(4), 'little')     # DWORD
        EncryptionAlgorithm = int.from_bytes(self._GetSize(4), 'little') # DWORD
        ExtensionSize = int.from_bytes(self._GetSize(4), 'little')       # DWORD
        Label:bytes 
        ExtensionData:bytes
        MessageBody:bytes

        MessageClass = MESSAGE_CLASS_VALUES[MessageClass % len(MESSAGE_CLASS_VALUES)]

        if MessageSize > AllocationBodySize:
            AllocationBodySize = MessageSize

        # 根据HashAlgorithm设置加密类型
        LowHashAlgorithm = self._GetBits(HashAlgorithm, 0, 3)
        if LowHashAlgorithm == 4:
            HashAlgorithm = 0x00008004
        elif LowHashAlgorithm == 1:
            HashAlgorithm = 0x00008001
        elif LowHashAlgorithm == 2:
            HashAlgorithm = 0x00008002
        elif LowHashAlgorithm == 3:
            HashAlgorithm = 0x00008003
        elif LowHashAlgorithm == 0xC:
            HashAlgorithm = 0x0000800C
        elif LowHashAlgorithm == 0xE:
            HashAlgorithm = 0x0000800E        
        else:
            HashAlgorithm = 0x0000800E

        # EncryptionAlgorithm
        LowEncryptionAlgorithm = self._GetBits(EncryptionAlgorithm, 0, 3)
        if LowEncryptionAlgorithm == 1:
            EncryptionAlgorithm = 0x00006801
        elif LowEncryptionAlgorithm == 2:
            EncryptionAlgorithm = 0x00006802
        elif LowEncryptionAlgorithm == 0:
            EncryptionAlgorithm = 0x00006800
        elif LowEncryptionAlgorithm == 0xE:
            EncryptionAlgorithm = 0x0000680E
        elif LowEncryptionAlgorithm == 0xF:
            EncryptionAlgorithm = 0x0000680F
        else:
            EncryptionAlgorithm = 0x00006801

        if LabelLength > 1:
            if LabelLength > 0xFA:
                LabelLength = 0xFA
            Label = self._makeUnicodeStr(LabelLength - 1)
        else:
            LabelLength = 0
            Label = b''
            
        ExtensionData = b'\x00' * ExtensionSize

        if MessageSize % 2:
            MessageSize -= 1
        elif MessageSize <= 3:
            MessageSize = 4

        
        MessageBody = self._makeUnicodeStr((MessageSize - 1) // 2)
      
        pack = MessagePropertiesHeader(Flags=Flags, LabelLength=LabelLength, MessageClass=MessageClass, CorrelationID=CorrelationID, BodyType=BodyType, ApplicationTag=ApplicationTag, MessageSize=MessageSize, AllocationBodySize=AllocationBodySize, PrivacyLevel=PrivacyLevel, HashAlgorithm=HashAlgorithm, EncryptionAlgorithm=EncryptionAlgorithm, ExtensionSize=ExtensionSize, Label=Label, ExtensionData=ExtensionData, MessageBody=MessageBody).pack()
        #pack += b'\x61\x00\xb0\xb0'
        pack = pack.ljust(len(pack) + (4 - len(pack) % 4) % 4, b'\x00')
        return pack

    def _GetDebugHeader(self):
        Flags = self._GetSize(2)
        QueueIdentifier = self._GetSize(16)
        QT = self._GetBits(Flags[0], 0, 1)
        # print(Flags, QT, QueueIdentifier)
        # Flags = self._SetBits(Flags[0], 0, 1, 0) + Flags[1:]
        # QT = self._GetBits(Flags[0], 0, 1)
        if QT != 1:
            QueueIdentifier = b''
        
        return DebugHeader(Flags=Flags, QueueIdentifier=QueueIdentifier).pack()

    def _GetMultiQueueFormatHeader(self):
        destination = self._GetMQFAddressHeader(0)
        administration  = self._GetMQFAddressHeader(1)
        response  = self._GetMQFAddressHeader(2)
        signature  = self._GetMQFSignatureHeader()
        return destination + administration + response + signature

    def _GetSoapHeader(self):
        headerDataLength = int.from_bytes(self._GetSize(4), 'little')
        bodyDataLength = int.from_bytes(self._GetSize(4), 'little')
        # print(headerDataLength, bodyDataLength)
        # if headerDataLength % 2:
        #     headerDataLength -= 1
        # elif headerDataLength <= 3:
        #     headerDataLength = 4
        
        # if bodyDataLength % 2:
        #     bodyDataLength -= 1
        # elif bodyDataLength <= 3:
        #     bodyDataLength = 4
        # print(headerDataLength, bodyDataLength)
        # headerData = self._makeUnicodeStr((headerDataLength - 2) // 2)
        # bodyData = self._makeUnicodeStr((bodyDataLength - 2) // 2)
        headerData = self._makeUnicodeStr((headerDataLength - 1))
        bodyData = self._makeUnicodeStr((bodyDataLength - 1))

        soapHeader = SoapHeader(HeaderDataLength = headerDataLength, BodyDataLength = bodyDataLength, Header = headerData, Body = bodyData)
        return soapHeader.pack()

    def _GetSRMPEnvelopeHeader(self):
        HeaderId = self._GetSize(2)
        DataLength = int.from_bytes(self._GetSize(4), 'little')

        DataLength |= 1
        data = self._makeUnicodeStr((DataLength - 1) / 2)

        srmp = SRMPEnvelopeHeader(HeaderId=HeaderId, DataLength=DataLength, Data=data)

    def _GetMQFAddressHeader(self, type):
        HeaderID = 0
        if type == 0:
            HeaderID = 0x0064
        elif type == 1:
            HeaderID = 0x00C8
        elif type == 2:
            HeaderID = 0x012C
        elif type == 3:
            HeaderID = 0x015E

        # ElementCount = int.from_bytes(self._GetSize(4), 'little')
        ElementCount = 0
        FormatNameList = self._GetMQFFormatNameElement() * ElementCount
        FormatNameList = FormatNameList.ljust(len(FormatNameList) + (4 - len(FormatNameList) % 4) % 4, b'\x00')
        
        HeaderSize = 0xC + len(FormatNameList)
        
        mqf = MQFAddressHeader(HeaderSize=HeaderSize, HeaderID=HeaderID, ElementCount=ElementCount, FormatNameList=FormatNameList)

        return mqf.pack()

    # TODO 生成不同类型的format name
    def _GetMQFFormatNameElement(self):
        return b'\x02\x00' + b'\xD1\x58\x73\x55\x50\x91\x95\x95\x49\x97\xB6\xE6\x11\xEA\x26\xC6' + b'\x01\x00\x00\x00' 
    
    def _GetMQFSignatureHeader(self):
        size = 0
        # signature = b'\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xAD\x4A\x9E\xBD\x36\xD9\xFA\x3D\x63\xA6\x56\xDA\xE8\x03\x00\x00'
        signature = b''

        return MQFSignatureHeader(data=signature, size=size).pack()

    def _GetAdminQueue(self, Flags):
        aq = self._GetBits(Flags[1], 5, 7)
        if aq in [2, 3]:
            self._GetSize(2)
            return b'a' * 4
        elif aq == 5:
            self._GetSize(2)
            return b'a' * 16
        elif aq == 6:
            self._GetSize(2)
            return self._GetPrivateQueueFormatName()
        elif aq == 7:
            return self._GetDirectQueueFormatName()
        else:
            self._GetSize(2)
            return b''

    def _GetDestinationQueue(self, Flags):
        dq = self._GetBits(Flags[1], 2, 4)
        if dq == 3:
            self._GetSize(2)
            return b'a' * 4
        elif dq == 5:
            self._GetSize(2)
            return b'a' * 16
        elif dq == 7:
            return self._GetDirectQueueFormatName()
        else:
            self._GetSize(2)
            return b''
        

    def _GetResponseQueue(self, Flags):
        dq = self._GetBits(Flags[2], 0, 2)
        if dq in [2, 3, 4]:
            self._GetSize(2)
            return b'a' * 4
        elif dq == 5:
            self._GetSize(2)
            return b'a' * 16
        elif dq == 6:
            self._GetSize(2)
            return self._GetPrivateQueueFormatName()
        elif dq == 7:
            return self._GetDirectQueueFormatName()
        else:
            self._GetSize(2)
            return b''
    
    def _GetPrivateQueueFormatName(self):
        source = b'\xD1\x58\x73\x55\x50\x91\x95\x95\x49\x97\xB6\xE6\x11\xEA\x26\xC6'
        idt = b'a' * 4
        return source + idt

    def _GetDirectQueueFormatName(self):
        length = int.from_bytes(self._GetSize(2), 'little')
        if length < 3:
            length = 4
        if length % 2:
            length -= 1
        # DirectFormatName = self._makeUnicodeStr((length // 2) - 3)
        DirectFormatName = self._makeUnicodeSrc('OS:') + self._makeUnicodeStrNoZero((length // 2) - 6) + self._makeUnicodeSrc('\q')
        name = struct.pack("<H", length) + DirectFormatName
        # 四字节对齐
        name = name.ljust(len(name) + (4 - len(name) % 4) % 4, b'\x00')
        return name

    def _GetBaseHeader(self):
        Reserved = self._GetSize(1)
        Flags = self._GetSize(2)
        TimeToReachQueue = self._GetSize(4)
        return BaseHeader(Reserved=Reserved, Flags=Flags, TimeToReachQueue=TimeToReachQueue)
    
    def _GetInternalHeader(self):
        Flags = self._GetSize(2)
        internal = InternalHeader(Flags=Flags)
        return internal
    
    def _GetEstablishConnectionHeader(self):
        timeStamp = self._GetSize(4)
        flags = self._GetSize(1)
        OperatingSystem = b'\x10' + flags
        ClientGuid = b'\xD1\x58\x73\x55\x50\x91\x95\x95\x49\x97\xB6\xE6\x11\xEA\x26\xC6'
        ServerGuid = b'\x07\x89\xCD\x43\x4C\x39\x11\x8F\x44\x45\x90\x78\x90\x9E\xA0\xFC' 

        establishConnectionHeader = EstablishConnectionHeader(TimeStamp=timeStamp, OperatingSystem = OperatingSystem, ClientGuid=ClientGuid, ServerGuid=ServerGuid)
        return establishConnectionHeader

    def _GetConnectionParametersHeader(self):
        # TODO 调整recoverableAckTimeout 和ackTimeout的大小
        recoverableAckTimeout = self._GetSize(4)
        ackTimeout = self._GetSize(4)
        windowSize = self._GetSize(2)

        return ConnectionParametersHeader(RecoverableAckTimeout=recoverableAckTimeout, AckTimeout=ackTimeout, WindowSize=windowSize)
    
    def GetMessagePropertiesHeader(self):
        Flags = self._GetSize(1)
        LabelLength = self._GetSize(1)
        MessageClass = self._GetSize(2)
        CorrelationID = self._GetSize(20)
        BodyType = self._GetSize(4)
        ApplicationTag = self._GetSize(4)
        MessageSize = self._GetSize(4)
        AllocationBodySize = self._GetSize(4)
        PrivacyLevel = self._GetSize(4)
        HashAlgorithm = self._GetSize(4)
        EncryptionAlgorithm = self._GetSize(4)
        ExtensionSize = self._GetSize(4)
        messagePropertiesHeader = MessagePropertiesHeader(Flags=Flags, LabelLength=LabelLength, MessageClass=MessageClass, CorrelationID=CorrelationID, BodyType=BodyType, ApplicationTag=ApplicationTag, MessageSize=MessageSize, AllocationBodySize=AllocationBodySize, PrivacyLevel=PrivacyLevel, HashAlgorithm=HashAlgorithm, EncryptionAlgorithm=EncryptionAlgorithm, ExtensionSize=ExtensionSize)

        return messagePropertiesHeader

    def _SetBits(self, flags, start, end, data):
        width = end - start + 1
        mask = ((1 << width) - 1) << start
       
        flags = flags & ~mask
       
        flags |= ((data & ((1 << width) - 1)) << start)
        return flags.to_bytes(1, "little")

    def _GetBits(self, flags, start, end):
        return (flags >> start) & ((1 << (end - start + 1)) - 1)

    def _makeUnicodeStr(self, length):
        return ("a" * length).encode("utf-16le") + b"\x00\x00"
    
    def _makeUnicodeStrNoZero(self, length):
        return ("a" * length).encode("utf-16le")

    def _makeUnicodeSrc(self, src):
        return (src).encode("utf-16le")  

def send_msmq(fuzz_data):
    global fuzz_addr, recv_sock
    mq_sock = None
    try:
        packet = Packet(fuzz_data, len(fuzz_data))
        pack = packet.GetPacket()

        mq_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        mq_sock.settimeout(2)
        mq_sock.connect(("127.0.0.1", 1801))

        mq_sock.sendall(pack[0])
        data = mq_sock.recvfrom(1024)

        mq_sock.sendall(pack[1])
        data = mq_sock.recvfrom(1024)

        mq_sock.sendall(pack[2])
        data = mq_sock.recvfrom(1024)
        # print(f"Sent {len(fuzz_data)} bytes to MSMQ server and received response")
        # print(data)
        recv_sock.sendto(b"end", fuzz_addr)
    # except ConnectionResetError as e:
    #     recv_sock.sendto(b"end", fuzz_addr)
    #     print("ConnectionResetError")
    # except ConnectionAbortedError as e:
    #     recv_sock.sendto(b"end", fuzz_addr)
    #     print("ConnectionAbortedError")
    except socket.timeout as e:
        recv_sock.sendto(b"timeout", fuzz_addr)
        print("socket timeout")
    except Exception as e:
        recv_sock.sendto(b"end", fuzz_addr)
        print(f"Exception: {e}")
    
    if mq_sock != None:
        mq_sock.close()
    

establishConnectionBaseHeader = b'\xC0' + b'\x0b\x00' + b'\xFF\xFF\xFF\xFF'
establishConnectionInternalHeader = b'\x02\x00'
establishConnectionHeader = b'\x4E\xCA\xDE\x1D' + b'\x03'

connectionParameterBaseHeader = b'\xC0' + b'\x0b\x00' + b'\xFF\xFF\xFF\xFF'
establishConnectionInternalHeader = b'\x02\x00'
connectionParameterHeader = b'\xD8\x05\x00\x00\xC0\xD4\x01\x00\x40\x00'
# establishConnectionHeader = b'\xC0\x0b\x00\xFF\xFF\xFF\xFF\x02\x00\x4E\xCA\xDE\x1D\x03\xD8\x05\x00\x00\xC0\xD4\x01\x00\x40\x00'
# connectionParameterHeader = b'\xC0\x0b\x00\xFF\xFF\xFF\xFF\x02\x00\x4E\xCA\xDE\x1D\x03\xD8\x05\x00\x00\xC0\xD4\x01\x00\x40\x00'
# 什么其余header都没有
# userHeaderData = b'\xFF\xFF\xFF\xFF' + b'\x4C\x49\x4F\x52' + b'\xee\x08\x00\x00' + b'\x00\x1c\x28\x00'
# 包括transaction header
# userMessageBaseHeader = b'\x00' + b'\x2b\x00' + b'\x00\x46\x05\x00'
userMessageBaseHeader = b'\x00' + b'\x23\x00' + b'\x00\x46\x05\x00'
# userHeaderData = b'\xFF\xFF\xFF\xFF' + b'\x4C\x49\x4F\x52' + b'\xee\x08\x00\x00' + b'\x00\x1c\xb8\x10'
userHeaderData = b'\xFF\xFF\xFF\xFF' + b'\x4C\x49\x4F\x52' + b'\xee\x08\x00\x00' + b'\x00\x1c\xb8\x10'
DestinationQueue = b'\x1A\x00'
AdminQueue = b'\x1A\x00'
ResponseQueue = b'\x1A\x00'
ConnectorType = b'\x30\x17\xf3\x5d\x37\xdc\x3a\x9a\xc0\x48\x5a\x06\xce\xda\x54\x51'
transactionHeaderData = b'\x05\x00\x00\x00' + b'\x01\x00\x00\x00\x00\x00\x00\x00' + b'\x01\x00\x00\x00'
securityHeader = b''
messagePropertiesHeader = b'\x0F' + b'\x0F' + b'\x00\x00' + b'\x00' * 4 + b'\xD0\x07\x00\x00' * 2 + b'\x04\x80\x00\x00' + b'\x01\x66\x00\x00' + b'\x00' * 4
debugHeader = b'\x01\x00' + b'\x00\x00\x44\x55\x66\x44\x16\xa7\xd4\x41\x9b\xe2\x00\x84\x0e\x55'
sRMPEnvelopeHeader = b'\x01\x00' + b'\x20\x00\x00\x00'
soapHeader = b'\x02\x00\x00\x00' * 2
# multiQueueFormatHeader = b'\x00\x00\x00\x00' + b'\x00\x00\x00\x00' * 2
multiQueueFormatHeader = b''

def main():
    global fuzz_addr
    # data = b''
    # with open("packet.bin", "rb") as f:
    #     data = f.read()
    # send_msmq(data)
    # return
    print("Listening for UDP packets on port 20000 and forwarding to TCP port 1801")
    while True:
        print("Waiting for UDP packet...")
        data, fuzz_addr = recv_sock.recvfrom(4096)
        print(f"Received {len(data)} bytes from {fuzz_addr}")

        if len(data) < 148:
            recv_sock.sendto(b"end", fuzz_addr)
            continue
        
        send_msmq(data)

import uuid


real = [0x10, 0x00, 0x03, 0x00, 0x4C, 0x49, 0x4F, 0x52, 0xB0, 0x08, 0x00, 0x00, 0x00, 0x46, 0x05, 0x00,
0xD1, 0x58, 0x73, 0x55, 0x50, 0x91, 0x95, 0x95, 0x49, 0x97, 0xB6, 0xE6, 0x11, 0xEA, 0x26, 0xC6,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xFF, 0xFF, 0xFF, 0xFF, 0x4C, 0x49, 0x4F, 0x52, 0xEE, 0x08, 0x00, 0x00, 0x00, 0x1C, 0x28, 0x00,
0x1A, 0x00, 0x4F, 0x00, 0x53, 0x00, 0x3A, 0x00,
0x61, 0x00, 0x30, 0x00, 0x34, 0x00, 0x62, 0x00,
0x6D, 0x00, 0x30, 0x00, 0x32, 0x00, 0x5C, 0x00,
0x71, 0x00, 0x00, 0x00, 0x01, 0x00, 0x1C, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0x00, 0x00,
0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00,
0xAD, 0x4A, 0x9E, 0xBD, 0x36, 0xD9, 0xFA, 0x3D,
0x63, 0xA6, 0x56, 0xDA, 0xE8, 0x03, 0x00, 0x00,
0x0F, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xD0, 0x07, 0x00, 0x00, 0xD0, 0x07, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x04, 0x80, 0x00, 0x00,
0x01, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x6D, 0x00, 0x71, 0x00, 0x73, 0x00, 0x65, 0x00,
0x6E, 0x00, 0x64, 0x00, 0x65, 0x00, 0x72, 0x00,
0x20, 0x00, 0x6C, 0x00, 0x61, 0x00, 0x62, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x00, 0x00]

def test():
    # with open("output.bin", "rb") as f:
    #     data = f.read()
    # global real
    
    # for i in range(1000):
    #     real.append(0x61)
    #     real.append(0x00)
    # real = bytes(real)

    
    global userHeaderData, transactionHeaderData, messagePropertiesHeader
    headerData = establishConnectionBaseHeader + establishConnectionInternalHeader + establishConnectionHeader + connectionParameterBaseHeader + establishConnectionInternalHeader + connectionParameterHeader + userMessageBaseHeader + userHeaderData + DestinationQueue + AdminQueue + ResponseQueue + ConnectorType + transactionHeaderData + securityHeader + messagePropertiesHeader + debugHeader + soapHeader + multiQueueFormatHeader
    packet = Packet(headerData, len(headerData))
    pack = packet.GetPacket()

    with open("packet.bin", "wb") as f:
        f.write(headerData)
    
    return
    mq_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mq_sock.settimeout(2)
    mq_sock.connect(("127.0.0.1", 1801))

    mq_sock.sendall(pack[0])
    print(f"Forwarded {len(pack[0])} bytes to TCP ")
    buf = mq_sock.recvfrom(1024)
    print(f"Received {len(buf[0])} bytes from TCP")

    mq_sock.sendall(pack[1])
    print(f"Forwarded {len(pack[1])} bytes to TCP ")
    buf = mq_sock.recvfrom(1024)
    print(f"Received {len(buf[0])} bytes from TCP")
    
    # for i in range(len(real)):
    #     if real[i] != pack[2][i]:
    #         print(f"Diff at {i+1}: real {real[i]} vs pack {pack[2][i]}")
    mq_sock.sendall(pack[2])
   
    print(f"Forwarded {len(pack[2])} bytes to TCP ")
    buf = mq_sock.recvfrom(1024)
    print(f"Received {len(buf[0])} bytes from TCP")
    mq_sock.close()

if __name__ == "__main__":
    main()