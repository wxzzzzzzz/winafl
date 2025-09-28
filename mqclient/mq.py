import socket
import struct
from dataclasses import dataclass
from typing import Tuple

recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
recv_sock.bind(("127.0.0.1", 20000))
fuzz_addr = 0

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
    Flags: int              # byte
    LabelLength: int        # byte
    MessageClass:int        # WORD
    CorrelationID:bytes     # 20 byte
    BodyType:int            # DWORD
    ApplicationTag:int      # DWORD
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
        fmt = '<BBH20sIIIIIIII{}s{}s{}s'.format(self.LabelLength, self.ExtensionSize, self.MessageSize)
        return struct.pack(fmt,
                           self.Flags,
                           self.LabelLength,
                           self.MessageClass,
                           self.CorrelationID,
                           self.BodyType, self.ApplicationTag, self.MessageSize, self.AllocationBodySize, self.PrivacyLevel, self.HashAlgorithm, self.EncryptionAlgorithm, self.ExtensionSize, self.Label, self.ExtensionData, self.MessageBody)

@dataclass
class DebugHeader:
    Flags:int               # WORD
    QueueIdentifier:bytes   # 16 byte
    Reserved:int = 0          # WORD

    def pack(self) -> bytes:
        fmt = '<HH16s'
        return struct.pack(fmt,
                           self.Flags,
                           self.Reserved,
                           self.QueueIdentifier)
dataclass
class UserHeader:
    QueueManagerAddress:bytes            # WORD
    TimeToBeReceived:int                 # DWORD
    SentTime:int
    MessageID:int
    Flags:int
    DestinationQueue:bytes
    AdminQueue:bytes
    ResponseQueue:bytes
    SourceQueueManager:bytes = b'\xC6\x26\xEA\x11\xE6\xB6\x97\x49\x95\x95\x91\x50\x55\x73\x58\xD1'             # WORD

    def __post_init__(self):
        self.DestinationQueue = self._GetDestinationQueue()
        self.AdminQueue = self._GetAdminQueue()
        self.ResponseQueue = self._GetResponseQueue()
    
    def pack(self) -> bytes:
        pass

@dataclass
class TransactionHeader:
    Flags:int
    TxSequenceID:bytes
    TxSequenceNumber:int
    PreviousTxSequenceNumber:int 
    ConnectorQMGuid:bytes

@dataclass
class SecurityHeader:
    Flags:int                   # WORD
    SenderIdSize:bytes          # WORD
    EncryptionKeySize:int       # WORD
    SignatureSize:int           # WORD
    SenderCertSize:int
    ProviderInfoSize:int

@dataclass
class MQFAddressHeader:
    HeaderSize:int
    HeaderID:int
    ElementCount:int
    FormatNameList:bytes
    Reserved:int = 0

@dataclass
class SoapHeader:
    HeaderDataLength:int
    Header:bytes
    BodyDataLength:int
    Body :bytes
    HeaderSectionID:int = 0x0320
    Reserved:int = 0
    BodySectionID:int = 0x0384
    Reserved1:int = 0
    
@dataclass
class SRMPEnvelopeHeader:
    HeaderId:int
    DataLength:int
    Data:bytes
    Reserved:int = 0


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
    
    def GetPacket(self):
        baseHeader = self._GetBaseHeader()
        internalHeader = self._GetInternalHeader(0)
        internalHeader_pack = internalHeader.pack()
        establishConnectionHeader = self._GetEstablishConnectionHeader()
        establishConnectionHeader_pack = establishConnectionHeader.pack()

        baseHeader.PacketSize = len(internalHeader_pack) + len(establishConnectionHeader_pack) + 16
        establishConnection_pack = baseHeader.pack() + internalHeader_pack + establishConnectionHeader_pack
        
        return [establishConnection_pack]
        

    def _GetEstablishPacket(self, baseHeader, internalHeader):
        Flags = self._GetSize(2)
        self._SetBits(Flags, 0, 4, 18)
        
        return 

        establishConnectionHeader = self._GetEstablishConnectionHeader()
        internalHeader_pack = internalHeader.pack()
        establishConnectionHeader_pack = establishConnectionHeader.pack()
        baseHeader.PacketSize = len(internalHeader_pack) + len(establishConnectionHeader_pack)

        return baseHeader.pack() + internalHeader_pack + establishConnectionHeader_pack
    
    def _GetConnectionParameterPacket(self):
        connectionParametersHeader = self.gen_ConnectionParametersHeader()
        flags = self.internalHeader.Flags
        self.internalHeader.Flags = (flags & 0xF0) | 3

        connectionParametersHeader_pack = connectionParametersHeader.pack()
        self.baseHeader.PacketSize = len(self.internalHeader) + len(connectionParametersHeader_pack) + 16

        connection_pack = self.baseHeader.pack() + self.internalHeader.pack() + connectionParametersHeader_pack.pack()

        return connection_pack

    def _GetUserHeader(self):
        SourceQueueManager = self._GetSize(16)
        QueueManagerAddress = self._GetSize(2)
        TimeToBeReceived = self._GetSize(4)
        SentTime = self._GetSize(4)
        MessageID = self._GetSize(4)
        Flags = self._GetSize(2)

        userHeader = UserHeader(SourceQueueManager=SourceQueueManager, QueueManagerAddress=QueueManagerAddress, TimeToBeReceived=TimeToBeReceived, SentTime=SentTime, MessageID=MessageID, Flags=Flags)
        userHeader.AdminQueue = self._GetAdminQueue(userHeader)
        userHeader.DestinationQueue = self._GetDestinationQueue(userHeader)
        userHeader.ResponseQueue = self._GetResponseQueue(userHeader)


    def _GetTransactionHeader(self):
        Flags = self._GetSize(4)
        TxSequenceID = self._GetSize(8)
        TxSequenceNumber = self._GetSize(4)
        PreviousTxSequenceNumber = TxSequenceNumber - 1
        ConnectorQMGuid = None

        CG = self._GetBits(Flags, 0, 1)
        if CG:
            ConnectorQMGuid = b'\xC6\x26\xEA\x11\xE6\xB6\x97\x49\x95\x95\x91\x50\x55\x73\x58\xD1'
        
        return TransactionHeader(Flags=Flags, TxSequenceID=TxSequenceID, TxSequenceNumber=TxSequenceNumber, PreviousTxSequenceNumber=PreviousTxSequenceNumber, ConnectorQMGuid=ConnectorQMGuid)
   
    def _GetSecurityHeader(self):
        Flags = self._GetSize(2)
        SenderIdSize = self._GetSize(2)
        EncryptionKeySize = self._GetSize(2)
        SignatureSize = self._GetSize(2)
        SenderCertSize = self._GetSize(4)
        ProviderInfoSize = self._GetSize(4)

        ProviderInfo = self._GetSize(4) + b'a' * (ProviderInfoSize - 4)
        pass

    def _GetDebugHeader(self):
        Flags = self._GetSize(2)
        QT = self._GetBits(Flags, 0, 2)
        QueueIdentifier = None

        if QT != 1:
            QueueIdentifier = b'a' * 16
        
        return DebugHeader(Flags=Flags, QueueIdentifier=QueueIdentifier)

    def _GetMultiQueueFormatHeader(self):
        destination = self._GetMQFAddressHeader(0)
        administration  = self._GetMQFAddressHeader(1)
        response  = self._GetMQFAddressHeader(2)
        signature  = self._GetMQFAddressHeader(3) 

        return destination + administration + response + signature

    def _GetSoapHeader(self):
        headerDataLength = self._GetSize(4)
        bodyDataLength = self._GetSize(4)
        headerData = self._makeUnicodeStr(headerDataLength)
        bodyData = self._makeUnicodeStr(bodyDataLength)

        SoapHeader(HeaderDataLength = headerDataLength, BodyDataLength = bodyDataLength, Header = headerData, Body = bodyData)

    def _GetSRMPEnvelopeHeader(self):
        HeaderId = self._GetSize(2)
        DataLength = self._GetSize(4)
        data = self._makeUnicodeStr(DataLength)

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

        ElementCount = self._GetSize(4)
        FormatNameList = self._GetMQFFormatNameElement() * ElementCount

        mqf = MQFAddressHeader(HeaderID=HeaderID, ElementCount=ElementCount, FormatNameList=FormatNameList)
        mqf.HeaderSize = 0xC + len(FormatNameList)

        return mqf

    def _GetMQFFormatNameElement(self):
        return b'\x00\x01' + b'a' * 16

    def _GetAdminQueue(self, userHeader):
        aq = self._GetBits(userHeader.Flags, 13, 16)
        if aq in [2, 3]:
            return self._GetSize(4)
        elif aq == 5:
            return self._GetSize(16)
        elif aq == 6:
            return self._GetSize(20)
        elif aq == 7:
            return self._GetDestinationQueue()
        else:
            return None

    def _GetDestinationQueue(self, userHeader):
        dq = self._GetBits(userHeader.Flags, 10, 13)
        if dq == 3:
            return self._GetSize(4)
        elif dq == 5:
            return self._GetSize(16)
        elif dq == 7:
            return self._GetDirectQueueFormatName()
        else:
            return None

    def _GetResponseQueue(self, userHeader):
        dq = self._GetBits(userHeader.Flags, 16, 19)
        if dq in [2, 3, 4]:
            return self._GetSize(4)
        elif dq == 5:
            return self._GetSize(16)
        elif dq == 6:
            return self._GetSize(20)
        elif dq == 7:
            return self._GetDestinationQueue()
        else:
            return None

    def _GetDirectQueueFormatName(self):
        size = self._GetSize(2)
        DirectFormatName = b'a' * int.from_bytes(size, 'little')
        return size + DirectFormatName

    def _GetBaseHeader(self):
        Reserved = self._GetSize(1)
        Flags = self._GetSize(2)
        TimeToReachQueue = self._GetSize(4)
        return BaseHeader(Reserved=Reserved, Flags=Flags, TimeToReachQueue=TimeToReachQueue)
    
    def _GetInternalHeader(self, type):
        Flags = self._GetSize(2)
        if type == 0:
            Flags = self._SetBits(Flags[0], 0, 4, 2) + Flags[1:]
        elif type == 1:
            Flags = self._SetBits(Flags[0], 0, 4, 3) + Flags[1:]
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

    def GetConnectionParametersHeader(self):
        connectionParametersHeader = ConnectionParametersHeader()
        connectionParametersHeader.RecoverableAckTimeout = self._GetSize(4)
        connectionParametersHeader.AckTimeout = self._GetSize(4)
        connectionParametersHeader.WindowSize = self._GetSize(2)

        return connectionParametersHeader
    
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
        if length % 2 != 0:
            length += 1
        
        size = (length - 1) / 2
        return text.encode("a" * size) + b"\x00\x00"

def recvfrom_msmq(mq_sock):
    global fuzz_addr
    try:
        print(fuzz_addr)
        data = mq_sock.recvfrom(1024)
        print(f"Received {len(data[0])} bytes from TCP")
        recv_sock.sendto(b"end", fuzz_addr)
    except ConnectionResetError as e:
        recv_sock.sendto(b"end", fuzz_addr)
        print(e)
    except socket.timeout as e:
        recv_sock.sendto(b"timeout", fuzz_addr)
        print(e)

data = b'\xC0\x0b\x00\xFF\xFF\xFF\xFF\x02\x00\x4E\xCA\xDE\x1D\x03'
# def main():
#     global fuzz_addr
#     print("Listening for UDP packets on port 20000 and forwarding to TCP port 1801")
#     while True:
#         print("Waiting for UDP packet...")
#         data, fuzz_addr = recv_sock.recvfrom(4096)
#         print(f"Received {len(data)} bytes from {fuzz_addr}")

#         mq_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         mq_sock.settimeout(2)
#         mq_sock.connect(("127.0.0.1", 1801))

#         mq_sock.sendall(data)
#         print(f"Forwarded {len(data)} bytes to TCP ")

#         recvfrom_msmq(mq_sock)

#         mq_sock.close()

def test():
    # with open("output.bin", "rb") as f:
    #     data = f.read()
    packet = Packet(data, len(data))
    # pack = packet.GetPacket()
    # buf = pack[0]
    # print(buf)
    # mq_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # mq_sock.settimeout(2)
    # mq_sock.connect(("127.0.0.1", 1801))

    # mq_sock.sendall(buf)
    # print(f"Forwarded {len(buf)} bytes to TCP ")
    # buf = mq_sock.recvfrom(1024)
    # print(f"Received {len(buf[0])} bytes from TCP")
    # mq_sock.close()
test()