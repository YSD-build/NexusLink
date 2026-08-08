import urllib.request, urllib.error, json, threading, time, sys, re

BASE = sys.argv[1] if len(sys.argv) > 1 else 'http://127.0.0.1:7001'
PASSWORD = sys.argv[2] if len(sys.argv) > 2 else 'admin123'


def do_req(method, path, data=None, headers=None, cookie=None, xff=None):
    url = BASE + path
    h = dict(headers or {})
    body = None
    if data is not None:
        body = data if isinstance(data, bytes) else json.dumps(data).encode()
        h.setdefault('Content-Type', 'application/json')
    if cookie:
        h['Cookie'] = f'session={cookie}'
    if xff:
        h['X-Forwarded-For'] = xff
    req = urllib.request.Request(url, data=body, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.getcode(), dict(resp.getheaders()), resp.read()
    except urllib.error.HTTPError as e:
        try:
            return e.code, dict(e.headers), e.read()
        except Exception:
            return e.code, dict(e.headers), b''
    except Exception as e:
        return -1, {}, str(e).encode()


def jparse(raw):
    try:
        return json.loads(raw)
    except Exception:
        return None


def extract_session(hdrs):
    sc = hdrs.get('Set-Cookie', '')
    m = re.search(r'session=([^;]+)', sc)
    return m.group(1) if m else None


def functional():
    print("\n=== Web 功能测试 ===")
    # 1) 未授权访问受保护 API -> 期望 401
    for p in ['/api/status', '/api/config', '/api/logs', '/api/proxies']:
        c, h, b = do_req('GET', p)
        print(f"  [未授权 {p}] HTTP {c} -> {'PASS' if c == 401 else 'FAIL'}")
    # 2) 正确登录
    c, h, b = do_req('POST', '/api/login', {'password': PASSWORD})
    cookie = csrf = None
    if c == 200:
        cookie = extract_session(h)
        jb = jparse(b)
        csrf = jb.get('csrf_token') if jb else None
        sc = h.get('Set-Cookie', '').lower()
        print(f"  [正确登录] 200 | cookie={'有' if cookie else '无'} | csrf={'有' if csrf else '无'} | HttpOnly={'是' if 'httponly' in sc else '否'} | SameSite=Strict={'是' if 'samesite=strict' in sc else '否'}")
    else:
        print(f"  [正确登录] FAIL HTTP {c}")
    # 3) 授权访问（含 config 不泄露 token）
    for p in ['/api/status', '/api/config', '/api/proxies', '/api/logs']:
        c, h, b = do_req('GET', p, cookie=cookie)
        extra = ''
        if p == '/api/config':
            jb = jparse(b)
            leak = bool(jb and 'token' in jb)
            extra = f" | token泄露={'是⚠️' if leak else '否✓'}"
        print(f"  [授权 {p}] HTTP {c}{extra} -> {'PASS' if c == 200 else 'FAIL'}")
    # 4) CSRF 缺失应拒
    c, h, b = do_req('POST', '/api/logout', cookie=cookie)
    print(f"  [CSRF缺失 POST /api/logout] HTTP {c} -> {'PASS(403拒)' if c == 403 else 'FAIL'}")
    # 5) CSRF 正确应通过（随后 session 失效）
    c, h, b = do_req('POST', '/api/logout', cookie=cookie, headers={'X-CSRF-Token': csrf})
    print(f"  [CSRF正确 POST /api/logout] HTTP {c} -> {'PASS' if c == 200 else 'FAIL'}")
    return cookie


def stress(conc, dur, label):
    c, h, b = do_req('POST', '/api/login', {'password': PASSWORD})
    cookie = extract_session(h)
    cnt = {'ok': 0, 'fail': 0, 'to': 0}
    lk = threading.Lock()
    deadline = time.time() + dur

    def worker():
        while time.time() < deadline:
            try:
                cc, hh, bb = do_req('GET', '/api/status', cookie=cookie)
                with lk:
                    cnt['ok' if cc == 200 else 'fail'] += 1
            except Exception:
                with lk:
                    cnt['to'] += 1

    ts = [threading.Thread(target=worker, daemon=True) for _ in range(conc)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    total = cnt['ok'] + cnt['fail'] + cnt['to']
    print(f"\n=== Web压力[{label}] 并发={conc} 持续={dur}s ===")
    print(f"  成功={cnt['ok']} 失败={cnt['fail']} 超时={cnt['to']} 总={total} 速率≈{total/dur:.0f}/s")


def lock_test():
    print("\n=== Web 登录失败锁定测试（XFF伪造IP避免污染真实IP）===")
    ip = '203.0.113.99'
    codes = []
    for i in range(7):
        c, h, b = do_req('POST', '/api/login', {'password': 'wrong' + str(i)}, xff=ip)
        codes.append(c)
    print(f"  连续错误密码状态码: {codes}")
    print(f"  前5次401/第6次起429(锁定) -> {'PASS' if codes[:5]==[401]*5 and codes[5]==429 else '观察'}")
    c, h, b = do_req('POST', '/api/login', {'password': PASSWORD}, xff=ip)
    print(f"  锁定后正确密码登录: HTTP {c} -> {'PASS(429拒)' if c == 429 else 'FAIL'}")


def malformed():
    print("\n=== Web 畸形请求测试 ===")
    c, h, b = do_req('POST', '/api/login', b'not json{', headers={'Content-Type': 'application/json'})
    print(f"  [非法JSON POST /api/login] HTTP {c} -> {'PASS(拒)' if c in (400, 401) else 'FAIL'}")
    c, h, b = do_req('GET', '/api/login')
    print(f"  [GET /api/login] HTTP {c} -> {'PASS(405拒)' if c == 405 else 'FAIL'}")
    big = b'A' * (5 * 1024 * 1024)
    t0 = time.time()
    c, h, b = do_req('POST', '/api/login', big)
    dt = time.time() - t0
    print(f"  [超长body 5MB POST /api/login] HTTP {c} 耗时={dt:.1f}s -> {'PASS(拒/未崩溃)' if c != -1 else 'FAIL(崩溃/OOM)'}")


if __name__ == '__main__':
    functional()
    stress(20, 15, '普通')
    stress(150, 30, '严格')
    lock_test()
    malformed()
    print("\n=== Web 测试完成 ===")
