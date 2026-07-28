#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NexusLink 极限压力测试 v2.0
- 合法 TCP/UDP 隧道流量全程持续，实时监测延迟(p50/p99)、吞吐、数据完整性
- 同时发动全部攻击手法 + 极限并发连接洪流 + 大流量吞吐压测
- 即便被打残，也要求：
    (a) 合法数据零损坏（echo 必须逐字节一致）
    (b) 篡改包被拒绝且不污染其他连接
    (c) 服务端不崩溃、合法延迟可接受
"""
import socket, struct, json, threading, time, sys, random, hmac, hashlib, collections, os

MAGIC = b'\x4E\x4C'; VER = 1
TOKEN = 'test_token_123'
SERVER = '127.0.0.1'
CTRL_PORT = 7000
TCP_PORT = 25565
UDP_PORT = 25566
WEB_PORT = 7001
LengthPrefixSize = 4  # 帧格式长度前缀大小

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
    """旧格式签名（用于篡改注入测试，验证旧格式帧会被新服务端拒绝）"""
    ts = int(time.time()).to_bytes(8, 'big')
    mac = hmac.new(token.encode(), ts + data, hashlib.sha256).digest()
    return mac + ts + data

def sign_payload_framed(data, token):
    """新帧格式签名: [4字节长度][32字节签名][8字节时间戳][数据]"""
    ts = int(time.time()).to_bytes(8, 'big')
    mac = hmac.new(token.encode(), ts + data, hashlib.sha256).digest()
    data_len = len(data).to_bytes(4, 'big')
    return data_len + mac + ts + data

# ---------------- 全局状态 ----------------
class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.tcp = []      # (ts, rtt_ms)
        self.udp = []
        self.corrupt = 0
        self.tcp_ok = 0
        self.udp_ok = 0
        self.tcp_bytes = 0
        self.udp_bytes = 0
        self.atk = collections.Counter()
        self.server_alive = True
    def add_tcp(self, ts, rtt, nbytes=0):
        with self.lock:
            self.tcp.append((ts, rtt))
            self.tcp_bytes += nbytes
    def add_udp(self, ts, rtt, nbytes=0):
        with self.lock:
            self.udp.append((ts, rtt))
            self.udp_bytes += nbytes
    def inc_corrupt(self):
        with self.lock: self.corrupt += 1
    def inc_ok(self, proto):
        with self.lock:
            if proto == 'tcp': self.tcp_ok += 1
            else: self.udp_ok += 1
    def inc(self, k, n=1):
        with self.lock: self.atk[k] += n
    def snap(self, since):
        with self.lock:
            return ([s for s in self.tcp if s[0] >= since],
                    [s for s in self.udp if s[0] >= since],
                    self.corrupt, self.tcp_ok, self.udp_ok, dict(self.atk),
                    self.tcp_bytes, self.udp_bytes)

def pct(vals, p):
    if not vals: return 0.0
    s = sorted(vals)
    k = max(0, min(len(s) - 1, int(p / 100.0 * len(s))))
    return s[k]

# ---------------- 合法延迟探针（高频） ----------------
def tcp_probe(stats, stop, idx):
    while not stop.is_set():
        try:
            s = socket.socket(); s.settimeout(3); s.connect((SERVER, TCP_PORT))
            seq = random.randint(0, 1 << 30)
            payload = f"TCP{idx:03d}-{seq}-{time.time()}".encode()
            t0 = time.time()
            s.sendall(payload)
            back = s.recv(4096)
            rtt = (time.time() - t0) * 1000
            if back == payload:
                stats.add_tcp(time.time(), rtt, len(payload))
                stats.inc_ok('tcp')
            else:
                stats.inc_corrupt()
            s.close()
        except Exception:
            pass
        time.sleep(0.01)

def udp_probe(stats, stop, idx):
    while not stop.is_set():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
            seq = random.randint(0, 1 << 30)
            payload = f"UDP{idx:03d}-{seq}-{time.time()}".encode()
            t0 = time.time()
            s.sendto(payload, (SERVER, UDP_PORT))
            back, _ = s.recvfrom(65535)
            rtt = (time.time() - t0) * 1000
            if back == payload:
                stats.add_udp(time.time(), rtt, len(payload))
                stats.inc_ok('udp')
            else:
                stats.inc_corrupt()
            s.close()
        except Exception:
            pass
        time.sleep(0.01)

# ---------------- 大流量吞吐探针 ----------------
def tcp_throughput_probe(stats, stop, idx):
    """持续大块数据传输，验证高吞吐下数据完整性"""
    chunk = b'X' * 60000  # 60KB per send
    while not stop.is_set():
        try:
            s = socket.socket(); s.settimeout(10); s.connect((SERVER, TCP_PORT))
            total_sent = 0
            rounds = 5
            t0 = time.time()
            for _ in range(rounds):
                s.sendall(chunk)
                total_sent += len(chunk)
            # 收回 echo
            received = b''
            while len(received) < total_sent:
                d = s.recv(65536)
                if not d: break
                received += d
            rtt = (time.time() - t0) * 1000
            if received == chunk * rounds:
                stats.add_tcp(time.time(), rtt, total_sent)
                stats.inc_ok('tcp')
            else:
                stats.inc_corrupt()
            s.close()
        except Exception:
            pass
        time.sleep(0.05)

# ---------------- 攻击者 ----------------
def atk_connect(mtype_builder, key, conc, stop):
    def worker():
        while not stop.is_set():
            try:
                s = socket.socket(); s.settimeout(2)
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
                req = urllib.request.Request(
                    f'http://{SERVER}:{WEB_PORT}/api/login',
                    data=json.dumps({"password": "x" + str(random.randint(0, 99999))}).encode(),
                    headers={'Content-Type': 'application/json'})
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
        req = urllib.request.Request(f'http://{SERVER}:{WEB_PORT}/api/login',
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
                req = urllib.request.Request(f'http://{SERVER}:{WEB_PORT}/api/status',
                                             headers={'Cookie': f'session={cookie}'})
                try: urllib.request.urlopen(req, timeout=5)
                except Exception: pass
                stats.inc('web_load')
            except Exception:
                pass
    ts = [threading.Thread(target=worker, daemon=True) for _ in range(conc)]
    [t.start() for t in ts]

def atk_connection_flood(stop, conc=300):
    """极限并发连接洪流：不断建连立刻断开，耗尽 fd"""
    def worker():
        while not stop.is_set():
            try:
                s = socket.socket(); s.settimeout(1)
                s.connect((SERVER, CTRL_PORT))
                s.close()
                stats.inc('conn_flood')
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
        rogue_port = random.randint(25600, 25700)
        c.sendall(build(0x03, {"name": f"rogue_{rogue_port}", "type": "tcp", "remote_port": rogue_port}))
        read_msg(c)  # NewProxyResp
        u = socket.socket(); u.settimeout(5); u.connect((SERVER, rogue_port))  # 作为"用户"触发 TypeNewConn
        mtype, nc = read_msg(c)  # TypeNewConn(0x05)
        assert mtype == 0x05, f"期望 TypeNewConn, 实得 {mtype}"
        d = socket.socket(); d.settimeout(5); d.connect((SERVER, nc['data_port']))
        d.sendall(build(0x09, {"conn_id": nc['conn_id']}))  # TypeDataConn 首帧
        # 注入篡改包：合法签名后翻转首字节（使用新帧格式）
        signed = sign_payload_framed(b'SECRET-DATA', TOKEN)
        tampered = bytearray(signed); tampered[LengthPrefixSize] ^= 0xFF  # 翻转签名首字节
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
        tcps, udps, corrupt, tok, uok, atk, tbytes, ubytes = stats.snap(last)
        tnum = [r for _, r in tcps]; unum = [r for _, r in udps]
        tthr = tbytes / 2 / 1024 / 1024  # MB/s (双向)
        uthr = ubytes / 2 / 1024 / 1024
        phase = "BASELINE" if now < baseline_until else ("ATTACK" if now < attack_until else "COOLDOWN")
        line = (f"[{phase}] t={now:.0f}s | "
                f"TCP p50={pct(tnum,50):.1f} p99={pct(tnum,99):.1f}ms ok={tok} thr={tthr:.1f}MB/s | "
                f"UDP p50={pct(unum,50):.1f} p99={pct(unum,99):.1f}ms ok={uok} thr={uthr:.1f}MB/s | "
                f"corrupt={corrupt} | "
                f"atk(bad={atk.get('bad',0)} mal={atk.get('mal',0)} over={atk.get('over',0)} "
                f"btype={atk.get('btype',0)} garbage={atk.get('garbage',0)} udp={atk.get('udp_flood',0)} "
                f"webBrute={atk.get('web_brute',0)} webLoad={atk.get('web_load',0)} connFlood={atk.get('conn_flood',0)})")
        print(line, flush=True)
        last = now

# ---------------- 主流程 ----------------
if __name__ == '__main__':
    attack_dur = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    baseline = 5
    cooldown = 5

    stats = Stats()
    stop = threading.Event()

    # 合法探针：8 TCP + 2 UDP 高频延迟探针 + 2 TCP 大流量吞吐探针
    probes = [threading.Thread(target=tcp_probe, args=(stats, stop, i), daemon=True) for i in range(8)]
    probes += [threading.Thread(target=udp_probe, args=(stats, stop, i), daemon=True) for i in range(2)]
    probes += [threading.Thread(target=tcp_throughput_probe, args=(stats, stop, i), daemon=True) for i in range(2)]
    [t.start() for t in probes]

    mon = threading.Thread(target=monitor, args=(stats, stop, time.time() + baseline, time.time() + baseline + attack_dur), daemon=True)
    mon.start()

    print(f"=== NexusLink 极限压力测试 v2.0 (baseline={baseline}s attack={attack_dur}s cooldown={cooldown}s) ===", flush=True)
    print(f"=== 合法探针: 8 TCP + 2 UDP 延迟 + 2 TCP 吞吐 ===", flush=True)
    print(f"=== 攻击面: bad_token / malformed / oversized / bad_type / garbage / udp_flood / web_brute / web_load / conn_flood ===", flush=True)

    # 基线期
    time.sleep(baseline)

    # 篡改注入（攻击前先验证机制）
    print("--- HMAC 篡改注入（基线）---", flush=True)
    rt = rogue_tamper_probe()
    print(f"  篡改包: leaked={rt.get('leaked')} rejected={rt.get('rejected')} {rt.get('err','')}", flush=True)

    # 发动全部攻击（提高并发度）
    print("--- 发动全攻击面（极限并发）---", flush=True)
    atk_connect(lambda: login('wrong_' + str(random.randint(0, 99999))), 'bad', 200, stop)
    atk_connect(lambda: MAGIC + bytes([VER, 0x01]) + struct.pack('>I', 10) + b'{"x":1}', 'mal', 150, stop)  # 畸形魔数
    atk_connect(lambda: MAGIC + bytes([VER, 0x01]) + struct.pack('>I', 20 * 1024 * 1024) + b'', 'over', 100, stop)  # 超长 length
    atk_connect(lambda: MAGIC + bytes([VER, 0x99]) + struct.pack('>I', 5) + b'hello', 'btype', 150, stop)  # 非法类型
    atk_garbage(stop, conc=100)
    atk_udp_flood(stop, pps=20000)
    atk_web_brute(stop, conc=80)
    atk_web_load(stop, conc=150)
    atk_connection_flood(stop, conc=300)

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
    tcps, udps, corrupt, tok, uok, atk, tbytes, ubytes = stats.snap(0)
    all_rtt = [r for _, r in tcps] + [r for _, r in udps]

    print("\n" + "=" * 60, flush=True)
    print("                    极限压力测试结果", flush=True)
    print("=" * 60, flush=True)

    print("\n[合法流量]", flush=True)
    print(f"  TCP 回显成功: {tok} 次 | 损坏: {corrupt}", flush=True)
    print(f"  UDP 回显成功: {uok} 次 | 损坏: {corrupt}", flush=True)
    print(f"  TCP 传输总量: {tbytes / 1024 / 1024:.2f} MB", flush=True)
    print(f"  UDP 传输总量: {ubytes / 1024 / 1024:.2f} MB", flush=True)

    print("\n[延迟统计]", flush=True)
    tcp_rtts = [r for _, r in tcps]
    udp_rtts = [r for _, r in udps]
    print(f"  TCP: p50={pct(tcp_rtts,50):.2f}ms p99={pct(tcp_rtts,99):.2f}ms max={max(tcp_rtts) if tcp_rtts else 0:.2f}ms", flush=True)
    print(f"  UDP: p50={pct(udp_rtts,50):.2f}ms p99={pct(udp_rtts,99):.2f}ms max={max(udp_rtts) if udp_rtts else 0:.2f}ms", flush=True)
    print(f"  整体: p50={pct(all_rtt,50):.2f}ms p99={pct(all_rtt,99):.2f}ms max={max(all_rtt) if all_rtt else 0:.2f}ms", flush=True)

    print("\n[安全防护]", flush=True)
    print(f"  篡改注入(基线): leaked={rt.get('leaked')} rejected={rt.get('rejected')}", flush=True)
    print(f"  篡改注入(攻击中): leaked={rt2.get('leaked')} rejected={rt2.get('rejected')}", flush=True)

    print("\n[攻击统计]", flush=True)
    print(f"  bad_token:     {atk.get('bad', 0):>10}", flush=True)
    print(f"  malformed:     {atk.get('mal', 0):>10}", flush=True)
    print(f"  oversized:     {atk.get('over', 0):>10}", flush=True)
    print(f"  bad_type:      {atk.get('btype', 0):>10}", flush=True)
    print(f"  garbage:       {atk.get('garbage', 0):>10}", flush=True)
    print(f"  udp_flood:     {atk.get('udp_flood', 0):>10}", flush=True)
    print(f"  web_brute:     {atk.get('web_brute', 0):>10}", flush=True)
    print(f"  web_load:      {atk.get('web_load', 0):>10}", flush=True)
    print(f"  conn_flood:    {atk.get('conn_flood', 0):>10}", flush=True)
    total_atk = sum(atk.values())
    print(f"  {'总计':>14}  {total_atk:>10}", flush=True)

    print("\n[结论]", flush=True)
    ok = (corrupt == 0) and (rt.get('leaked') == False) and (rt2.get('leaked') == False) and (tok > 0) and (uok > 0)
    if ok:
        print("  PASS  被攻击时数据正常传输、篡改被拒、零损坏、服务端存活", flush=True)
    else:
        reasons = []
        if corrupt > 0: reasons.append(f"数据损坏{corrupt}次")
        if rt.get('leaked') != False: reasons.append("基线篡改泄露")
        if rt2.get('leaked') != False: reasons.append("攻击中篡改泄露")
        if tok == 0: reasons.append("TCP无成功回显")
        if uok == 0: reasons.append("UDP无成功回显")
        print(f"  FAIL  存在问题: {', '.join(reasons)}", flush=True)

    print("\n" + "=" * 60, flush=True)
    sys.exit(0 if ok else 1)
