import socket, threading
def handle(c):
    try:
        while True:
            d = c.recv(4096)
            if not d: break
            c.sendall(d)
    except Exception:
        pass
    finally:
        c.close()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 9000))
s.listen(256)
while True:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
