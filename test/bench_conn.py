import socket, struct, json, threading, time, sys, random

MAGIC = b'\x4E\x4C'
VER = 1
TOKEN_OK = 'test_token_123'

def build_msg(mtype, payload):
    p = json.dumps(payload).encode()
    return MAGIC + bytes([VER, mtype]) + struct.pack('>I', len(p)) + p

def login(token):
    return build_msg(0x01, {"version": "v0.3.0", "token": token})

def malformed_magic():
    return b'\x00\x00' + bytes([VER, 0x01]) + struct.pack('>I', 10) + b'{"x":1}'

def oversized_len():
    # length 超 MaxMessageSize(10MB)，ReadMessage 先校验再分配，应被拒、不分配内存
    return MAGIC + bytes([VER, 0x01]) + struct.pack('>I', 20 * 1024 * 1024) + b''

def bad_type():
    return MAGIC + bytes([VER, 0x99]) + struct.pack('>I', 5) + b'hello'

# 多源 IP 模拟多 client（避免单 IP 触发 connGuard 封禁）
SRC_IPS = [f'127.0.0.{i}' for i in range(2, 201)]

class Counter:
    def __init__(self):
        self.lock = threading.Lock(); self.d = {}
    def inc(self, k):
        with self.lock:
            self.d[k] = self.d.get(k, 0) + 1
    def get(self):
        with self.lock:
            return dict(self.d)

def worker(cnt, mode, single_ip):
    try:
        s = socket.socket()
        s.settimeout(3)
        if not single_ip:
            try:
                s.bind((random.choice(SRC_IPS), 0))
            except Exception:
                pass
        s.connect(('127.0.0.1', 7000))
        if mode == 'ok':
            s.sendall(login(TOKEN_OK))
        elif mode == 'bad':
            s.sendall(login('wrong_' + str(random.randint(0, 99999))))
        elif mode == 'magic':
            s.sendall(malformed_magic())
        elif mode == 'over':
            s.sendall(oversized_len())
        elif mode == 'btype':
            s.sendall(bad_type())
        try:
            s.recv(1024)
            cnt.inc('resp_ok')
        except Exception:
            cnt.inc('resp_timeout')
        s.close()
        cnt.inc('connected')
    except Exception as e:
        cnt.inc('fail_' + type(e).__name__)

def run(conc, dur, mix, single_ip):
    cnt = Counter()
    deadline = time.time() + dur
    def loop():
        while time.time() < deadline:
            mode = random.choices(list(mix.keys()), weights=list(mix.values()))[0]
            worker(cnt, mode, single_ip)
    threads = [threading.Thread(target=loop, daemon=True) for _ in range(conc)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    return cnt.get()

if __name__ == '__main__':
    conc = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    dur = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    single = (len(sys.argv) > 3 and sys.argv[3] == 'single')
    mix = {'ok': 0.4, 'bad': 0.3, 'magic': 0.1, 'over': 0.1, 'btype': 0.1}
    tag = '单IP洪水(触发ban)' if single else '多源IP(模拟多client)'
    print(f'=== 连接层压测[{tag}] 并发={conc} 持续={dur}s ===', flush=True)
    print('结果:', json.dumps(run(conc, dur, mix, single), ensure_ascii=False), flush=True)
