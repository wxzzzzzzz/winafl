import socket
import struct
from dataclasses import dataclass
from typing import Tuple

recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
recv_sock.bind(("127.0.0.1", 20000))
fuzz_addr = 0

@dataclass
class BaseHeader:
    VersionNumber: int = 0x10   # BYTE
    Reserved: int = 0        # BYTE
    Flags: int            # WORD
    Signature: int = 0x524F494C      # DWORD
    PacketSize: int       # DWORD
    TimeToReachQueue: int # DWORD

    def pack(self) -> bytes:
        # '<' little-endian, B B H I I I
        return struct.pack('<BBHIII',
                           self.VersionNumber,
                           self.Reserved,
                           self.Flags,
                           self.Signature,
                           self.PacketSize,
                           self.TimeToReachQueue)

@dataclass
class InternalHeader:
    Reserved: int = 0 # WORD
    Flags: int = 0    # WORD

    def pack(self) -> bytes:
        return struct.pack('<HH', self.Reserved, self.Flags)
    
@dataclass
class ConnectionParametersHeader:
    RecoverableAckTimeout: int  # DWORD
    AckTimeout: int     # DWORD
    Reserved: int = 0    # WORD
    WindowSize: int # WORD

    
    
@dataclass
class EstablishConnectionHeader:
    ClientGuid: Tuple[int,int,int,bytes] = [0xC626EA11, 0xE6B6, 0x9749, 0x9595, 0x9150557358D1] # (d1,d2,d3,d4)
    ServerGuid: Tuple[int,int,int,bytes] = [0xFCA09E90, 0x7890, 0x4544, 0x8F11, 0x394C43CD8907]
    TimeStamp: int     # DWORD
    OperatingSystem: Tuple[int, int] = [0x10, 0] # WORD
    Reserved: int = 0     # WORD
    Padding: bytes = b'\x5a' * 512    # 512 bytes

    def pack(self) -> bytes:
        # GUID pack: <IHH8s
        c_d1, c_d2, c_d3, c_d4 = self.ClientGuid
        s_d1, s_d2, s_d3, s_d4 = self.ServerGuid
        re, flag = self.OperatingSystem
        fmt = '<IHH8sBBIHH512s'
        return struct.pack(fmt,
                           c_d1, c_d2, c_d3, c_d4,
                           s_d1, s_d2, s_d3, s_d4,
                           re, flag,
                           self.TimeStamp,
                           self.OperatingSystem,
                           self.Reserved,
                           self.Padding)
    
class Packet:
    def __init__(self, fuzz_data, len):
        self.fuzz_data = fuzz_data
        self.len = len
        self.index = 0
        self.baseHeader = self.gen_baseheader()
        self.internalHeader = self.gen_internalheader()

    def get_size(self, size):
        if (self.index + size) > self.len:
            return None
        
        return self.fuzz_data[self.index, self.index + size]
    
    def gen_connection_packet(self):
        connectionParametersHeader = self.gen_ConnectionParametersHeader()
        flags = self.internalHeader.Flags
        self.internalHeader.Flags = (flags & 0xF0) | 2

        connectionParametersHeader_pack = connectionParametersHeader.pack()
        self.baseHeader.PacketSize = len(self.internalHeader) + len(connectionParametersHeader_pack) + 16

        connection_pack = self.baseHeader.pack() + self.internalHeader.pack() + connectionParametersHeader_pack.pack()

        return connection_pack
    
    def gen_connectionParameter_packet(self):
        establishConnectionHeader = self.gen_EstablishConnectionHeader()
        flags = self.internalHeader.Flags
        self.internalHeader.Flags = (flags & 0xF0) | 3

    def gen_baseheader(self):
        Flags = self.get_size(2)
        TimeToReachQueue = self.get_size(4)
        return BaseHeader(Flags=Flags, TimeToReachQueue=TimeToReachQueue)
    
    def gen_internalheader(self, type):
        internal = InternalHeader()
        internal.Flags = (internal.Flags & 0xF0) | type
        return internal
    
    def gen_EstablishConnectionHeader(self):
        timeStamp = self.get_size(4)
        flags = self.get_size(1)
        establishConnectionHeader = EstablishConnectionHeader(TimeStamp=timeStamp, OperatingSystem = [0x10, flags])
        return establishConnectionHeader

    def gen_ConnectionParametersHeader(self):
        connectionParametersHeader = ConnectionParametersHeader()
        connectionParametersHeader.RecoverableAckTimeout = self.get_size(4)
        connectionParametersHeader.AckTimeout = self.get_size(4)
        connectionParametersHeader.WindowSize = self.get_size(2)

        return connectionParametersHeader
    
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

def main():
    global fuzz_addr
    print("Listening for UDP packets on port 20000 and forwarding to TCP port 1801")
    while True:
        print("Waiting for UDP packet...")
        data, fuzz_addr = recv_sock.recvfrom(4096)
        print(f"Received {len(data)} bytes from {fuzz_addr}")

        mq_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        mq_sock.settimeout(2)
        mq_sock.connect(("127.0.0.1", 1801))

        mq_sock.sendall(data)
        print(f"Forwarded {len(data)} bytes to TCP ")

        recvfrom_msmq(mq_sock)

        mq_sock.close()

main()