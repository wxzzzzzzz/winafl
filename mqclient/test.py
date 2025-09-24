import socket


mq_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
mq_sock.connect(("127.0.0.1", 1801))

data = b""
with open("output.bin", "rb") as r:
    data = r.read()

print(f"Read {len(data)} bytes from file")
mq_sock.sendall(b"a" * 512)
print(f"Forwarded {len(data)} bytes to TCP ")
try:
    data = mq_sock.recvfrom(1024)
    print(f"Received {len(data[0])} bytes from TCP")
except ConnectionResetError as e:
    print(e)
mq_sock.close()