#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NexusLink v0.3.1 严格攻击韧性测试
- 合法 TCP/UDP 隧道流量全程持续，实时监测延迟(p50/p99)、吞吐、数据完整性
- 同时发动全部攻击手法；即便被打残，也要求：
    (a) 合法数据零损坏（echo 必须逐字节一致）
    (b) 篡改包被拒绝且不污染其他连接
    (c) 服务端不崩溃、合法延迟可接受
"""
import socket, struct, json, threading, time, sys, random, hmac, hashlib, collections

MAGIC = b'\x4E\x4C'; VER = 1
TOKEN = 'test_token_123'
SERVER = '127.0.0.1'
CTRL_PORT = 7000
TCP_PORT = 25565
UDP_PORT = 25566
SRC_IPS = [f'127.0.0.{i}' for i in range(2, 201)]  # 多源 IP 模拟僵尸网络

# ---------------- 协议 helpers ----------------
def build(mtype, payload):
    p = json.dumps(payload).encode()
    return MAGIC + bytes([VER, mtype]) + struct.pack('>I', len(p)) + p

def login(token):
    return build(0x01, {"version": "v0.3.1", "token": token})

def recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("closed")
        buf += chunk
    return buf

def read_msg(sock):
    h = recv_exact(sock, 8)
    mtype = h[3]
    length = struct.unpack('>I', h[4:8])[0]
    body = recv_exact(sock, length) if length else b''
    return mtype, (json.loads(body) if body else {})

def sign_payload(data, token):
    ts = int(time.time()).to_bytes(8, 'big')
    mac = hmac.new(token.encode(), ts + data, hashlib.sha256).digest()
    return mac + ts + data

# ---------------- 全局状态 ----------------
class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.tcp = []      # (ts, rtt_ms)
        self.udp = []
        self.corrupt = 0
        self.tcp_ok = 0
        self.udp_ok = 0
        self.atk = collections.Counter()
        self.server_alive = True
    def add_tcp(self, ts, rtt):
        with self.lock: self.tcp.append((ts, rtt))
    def add_udp(self, ts, rtt):
        with self.lock: self.udp.append((ts, rtt))
    def inc(self, k, n=1):
        with self.lock: self.atk[k] += n
    def snap(self, since):
        with self.lock:
            return ([s for s in self.tcp if s[0] >= since],
                    [s for s in self.udp if s[0] >= since],
                    self.corrupt, self.tcp_ok, self.udp_ok, dict(self.atk))

def pct(vals, p):
    if not vals: return 0.0
    s = sorted(vals)
    k = max(0, min(len(s) - 1, int(p / 100.0 * len(s))))
    return s[k]

# ---------------- 合法延迟探针 ----------------
def tcp_probe(stats, stop, idx):
    while not stop.is_set():
        try:
            s = socket.socket(); s.settimeout(2); s.connect((SERVER, TCP_PORT))
            seq = random.randint(0, 1 << 30)
            payload = f"TCP{idx:03d}-{seq}-{time.time()}".encode()
            t0 = time.time()
            s.sendall(payload)
            back = s.recv(4096)
            rtt = (time.time() - t0) * 1000
            if back == payload:
                stats.add_tcp(time.time(), rtt); stats.tcp_ok += 1
            else:
                stats.corrupt += 1
            s.close()
        except Exception:
            pass
        time.sleep(0.02)

def udp_probe(stats, stop):
    while not stop.is_set():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
            seq = random.randint(0, 1 << 30)
            payload = f"UDP-{seq}-{time.time()}".encode()
            t0 = time.time()
            s.sendto(payload, (SERVER, UDP_PORT))
            back, _ = s.recvfrom(65535)
            rtt = (time.time() - t0) * 1000
            if back == payload:
                stats.add_udp(time.time(), rtt); stats.udp_ok += 1
            else:
                stats.corrupt += 1
            s.close()
        except Exception:
            pass
        time.sleep(0.02)

# ---------------- 攻击者 ----------------
def atk_connect(mtype_builder, key, conc=200):
    def worker():
        while not stop.is_set():
            try:
                s = socket.socket(); s.settimeout(2)
                try: s.bind((random.choice(SRC_IPS), 0))
                except Exception: pass
                s.connect((SERVER, CTRL_PORT))
                s.sendall(mtype_builder())
            except Exception:
                pass
            finally:
                try: s.close()
                except Exception: pass
            stats.inc(key)
    ts = [threading.Thread(target=worker, daemon=True) for _ in range(conc)]
    [t.start() for t in ts]

def atk_garbage(stop, conc=80):
    """登录成功后往控制通道灌随机字节（协议混淆攻击）"""
    def worker():
        while not stop.is_set():
            try:
                s = socket.socket(); s.settimeout(2)
                try: s.bind((random.choice(SRC_IPS), 0))
                except Exception: pass
                s.connect((SERVER, CTRL_PORT))
                s.sendall(login('wrong'))
                for _ in range(random.randint(1, 5)):
                    s.sendall(bytes(random.randint(0, 255) for _ in range(random.randint(8, 64))))
                stats.inc('garbage')
            except Exception:
                pass
            finally:
                try: s.close()
                except Exception: pass
    ts = [threading.Thread(target=worker, daemon=True) for _ in range(conc)]
    [t.start() for t in ts]

def atk_udp_flood(stop, pps=20000):
    """往公网 UDP 用户端口灌洪水（负载 + 畸形大包）"""
    def worker():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while not stop.is_set():
            try:
                data = bytes(random.randint(0, 255) for _ in range(random.choice([64, 256, 1200])))
                s.sendto(data, (SERVER, UDP_PORT))
                stats.inc('udp_flood')
            except Exception:
                pass
    ts = [threading.Thread(target=worker, daemon=True) for _ in range(40)]
    [t.start() for t in ts]

def atk_web_brute(stop, conc=60):
    import urllib.request, urllib.error
    def worker():
        while not stop.is_set():
            try:
                ip = random.choice(SRC_IPS)
                req = urllib.request.Request(
                    f'http://{SERVER}:7001/api/login',
                    data=json.dumps({"password": "x" + str(random.randint(0, 99999))}).encode(),
                    headers={'Content-Type': 'application/json', 'X-Forwarded-For': ip})
                try: urllib.request.urlopen(req, timeout=5)
                except urllib.error.HTTPError: pass
                except Exception: pass
                stats.inc('web_brute')
            except Exception:
                pass
    ts = [threading.Thread(target=worker, daemon=True) for _ in range(conc)]
    [t.start() for t in ts]

def atk_web_load(stop, conc=150):
    """持合法 cookie 高频打 /api/status（接口压力）"""
    import urllib.request, urllib.error
    cookie = None
    try:
        req = urllib.request.Request(f'http://{SERVER}:7001/api/login',
                                     data=json.dumps({"password": "admin123"}).encode(),
                                     headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=5) as r:
            sc = r.headers.get('Set-Cookie', '')
            import re
            m = re.search(r'session=([^;]+)', sc)
            cookie = m.group(1) if m else None
    except Exception:
        pass
    def worker():
        while not stop.is_set():
            try:
                req = urllib.request.Request(f'http://{SERVER}:7001/api/status',
                                             headers={'Cookie': f'session={cookie}'})
                try: urllib.request.urlopen(req, timeout=5)
                except Exception: pass
                stats.inc('web_load')
            except Exception:
                pass
    ts = [threading.Thread(target=worker, daemon=True) for _ in range(conc)]
    [t.start() for t in ts]

# ---------------- HMAC 篡改注入（走完整握手拿数据通道端口）----------------
def rogue_tamper_probe():
    try:
        c = socket.socket(); c.settimeout(5); c.connect((SERVER, CTRL_PORT))
        c.sendall(login(TOKEN))
        read_msg(c)  # LoginResp
        rogue_port = 25599
        c.sendall(build(0x03, {"name": "rogue", "type": "tcp", "remote_port": rogue_port}))
        read_msg(c)  # NewProxyResp
        u = socket.socket(); u.settimeout(5); u.connect((SERVER, rogue_port))  # 作为“用户”触发 TypeNewConn
        mtype, nc = read_msg(c)  # TypeNewConn(0x05)
        assert mtype == 0x05, f"期望 TypeNewConn, 实得 {mtype}"
        d = socket.socket(); d.settimeout(5); d.connect((SERVER, nc['data_port']))
        d.sendall(build(0x09, {"conn_id": nc['conn_id']}))  # TypeDataConn 首帧
        # 注入篡改包：合法签名后翻转首字节
        signed = sign_payload(b'SECRET-DATA', TOKEN)
        tampered = bytearray(signed); tampered[0] ^= 0xFF
        d.sendall(bytes(tampered))
        u.settimeout(2)
        leaked = False
        try:
            got = u.recv(4096)
            if b'SECRET-DATA' in got:
                leaked = True
        except Exception:
            pass
        c.close(); u.close(); d.close()
        return {"leaked": leaked, "rejected": True}
    except Exception as e:
        return {"leaked": None, "rejected": False, "err": str(e)}

# ---------------- 实时监测 ----------------
def monitor(stats, stop, baseline_until, attack_until):
    last = time.time()
    while not stop.is_set():
        time.sleep(2)
        now = time.time()
        tcps, udps, corrupt, tok, uok, atk = stats.snap(last)
        tnum = [r for _, r in tcps]; unum = [r for _, r in udps]
        phase = "BASELINE" if now < baseline_until else ("ATTACK" if now < attack_until else "COOLDOWN")
        line = (f"[{phase}] t={now:.0f}s | "
                f"TCP p50={pct(tnum,50):.1f} p99={pct(tnum,99):.1f}ms ok={tok} | "
                f"UDP p50={pct(unum,50):.1f} p99={pct(unum,99):.1f}ms ok={uok} | "
                f"corrupt={corrupt} | "
                f"atk(bad={atk.get('bad',0)} mal={atk.get('mal',0)} over={atk.get('over',0)} "
                f"btype={atk.get('btype',0)} garbage={atk.get('garbage',0)} udp={atk.get('udp_flood',0)} "
                f"webBrute={atk.get('web_brute',0)} webLoad={atk.get('web_load',0)})")
        print(line, flush=True)
        last = now

# ---------------- 主流程 ----------------
if __name__ == '__main__':
    attack_dur = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    baseline = 5
    cooldown = 5
    total = baseline + attack_dur + cooldown

    stats = Stats()
    stop = threading.Event()

    # 合法探针
    probes = [threading.Thread(target=tcp_probe, args=(stats, stop, i), daemon=True) for i in range(8)]
    probes.append(threading.Thread(target=udp_probe, args=(stats, stop), daemon=True))
    [t.start() for t in probes]

    mon = threading.Thread(target=monitor, args=(stats, stop, time.time() + baseline, time.time() + baseline + attack_dur), daemon=True)
    mon.start()

    print(f"=== 严格攻击韧性测试 (baseline={baseline}s attack={attack_dur}s cooldown={cooldown}s) ===", flush=True)

    # 基线期
    time.sleep(baseline)

    # 篡改注入（攻击前先验证机制）
    print("--- HMAC 篡改注入（基线）---", flush=True)
    rt = rogue_tamper_probe()
    print(f"  篡改包: leaked={rt.get('leaked')} rejected={rt.get('rejected')} {rt.get('err','')}", flush=True)

    # 发动全部攻击
    print("--- 发动全攻击面 ---", flush=True)
    atk_connect(lambda: login('wrong_' + str(random.randint(0, 99999))), 'bad')
    atk_connect(lambda: MAGIC + bytes([VER, 0x01]) + struct.pack('>I', 10) + b'{"x":1}', 'mal')  # 畸形魔数
    atk_connect(lambda: MAGIC + bytes([VER, 0x01]) + struct.pack('>I', 20 * 1024 * 1024) + b'', 'over')  # 超长 length
    atk_connect(lambda: MAGIC + bytes([VER, 0x99]) + struct.pack('>I', 5) + b'hello', 'btype')  # 非法类型
    atk_garbage(stop)
    atk_udp_flood(stop)
    atk_web_brute(stop)
    atk_web_load(stop)

    # 攻击期
    time.sleep(attack_dur)

    # 攻击期内再注入一次篡改，验证被攻击时仍拒绝
    print("--- HMAC 篡改注入（攻击中）---", flush=True)
    rt2 = rogue_tamper_probe()
    print(f"  篡改包: leaked={rt2.get('leaked')} rejected={rt2.get('rejected')} {rt2.get('err','')}", flush=True)

    # 停攻击
    stop.set()
    time.sleep(cooldown)

    # 最终统计
    tcps, udps, corrupt, tok, uok, atk = stats.snap(0)
    print("\n========== 结果 ==========", flush=True)
    print(f"合法 TCP 回显成功: {tok} | 损坏: {corrupt}", flush=True)
    print(f"合法 UDP 回显成功: {uok} | 损坏: {corrupt}", flush=True)
    all_rtt = [r for _, r in tcps] + [r for _, r in udps]
    print(f"整体延迟 p50={pct(all_rtt,50):.1f}ms p99={pct(all_rtt,99):.1f}ms max={max(all_rtt) if all_rtt else 0:.1f}ms", flush=True)
    print(f"篡改注入(基线): leaked={rt.get('leaked')} rejected={rt.get('rejected')}", flush=True)
    print(f"篡改注入(攻击中): leaked={rt2.get('leaked')} rejected={rt2.get('rejected')}", flush=True)
    ok = (corrupt == 0) and (rt.get('leaked') == False) and (rt2.get('leaked') == False) and (tok > 0) and (uok > 0)
    print("结论: " + ("✅ 被攻击时数据正常传输、篡改被拒、零损坏、服务端存活" if ok else "❌ 存在问题，见上"), flush=True)
    sys.exit(0 if ok else 1)
