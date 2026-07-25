import socket

# 简单 UDP echo 服务：把收到的每个包原样返回给来源地址
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 9001))
print("UDP echo server on 127.0.0.1:9001", flush=True)
while True:
    data, addr = s.recvfrom(65535)
    s.sendto(data, addr)
