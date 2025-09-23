import socket


recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
recv_sock.bind(("127.0.0.1", 20000))

mq_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
mq_sock.connect(("127.0.0.1", 1801))

print("Listening for UDP packets on port 20000 and forwarding to TCP port 1801")
while True:
    print("Waiting for UDP packet...")
    data, addr = recv_sock.recvfrom(4096)
    print(f"Received {len(data)} bytes from {addr}")

    mq_sock.sendall(data)
    print(f"Forwarded {len(data)} bytes to TCP ")