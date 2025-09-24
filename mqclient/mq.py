import socket


recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
recv_sock.bind(("127.0.0.1", 20000))
fuzz_addr = 0

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