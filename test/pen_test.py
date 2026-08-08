import socket, time, sys

TOKEN = b""  # 仅测试转发，不涉及认证
failures = []

def test_tcp():
    print("=== TCP 穿透测试 (127.0.0.1:25565 -> 9000 echo) ===")
    try:
        c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c.settimeout(5)
        c.connect(("127.0.0.1", 25565))
        for i in range(3):
            msg = f"tcp-ping-{i}-{time.time()}".encode()
            c.sendall(msg)
            back = c.recv(4096)
            if back == msg:
                print(f"  [OK] 回合 {i}: 收到回显 {back!r}")
            else:
                print(f"  [FAIL] 回合 {i}: 期望 {msg!r} 实际 {back!r}")
                failures.append(f"tcp round {i}")
        c.close()
    except Exception as e:
        print(f"  [FAIL] TCP 异常: {e}")
        failures.append(f"tcp exception: {e}")

def test_udp():
    print("=== UDP 穿透测试 (127.0.0.1:25566 -> 9001 echo) ===")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        for i in range(5):
            msg = f"udp-ping-{i}-{time.time()}".encode()
            s.sendto(msg, ("127.0.0.1", 25566))
            try:
                back, addr = s.recvfrom(65535)
            except socket.timeout:
                print(f"  [FAIL] 回合 {i}: 超时无回显")
                failures.append(f"udp round {i} timeout")
                continue
            if back == msg:
                print(f"  [OK] 回合 {i}: 收到回显 {back!r}")
            else:
                print(f"  [FAIL] 回合 {i}: 期望 {msg!r} 实际 {back!r}")
                failures.append(f"udp round {i} mismatch")
        s.close()
    except Exception as e:
        print(f"  [FAIL] UDP 异常: {e}")
        failures.append(f"udp exception: {e}")

def test_udp_large():
    print("=== UDP 大包测试 (接近 64K) ===")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        msg = b"X" * 63000
        s.sendto(msg, ("127.0.0.1", 25566))
        back, _ = s.recvfrom(65535)
        if back == msg:
            print(f"  [OK] 大包 {len(msg)} 字节回显一致")
        else:
            print(f"  [FAIL] 大包回显长度 {len(back)} != {len(msg)}")
            failures.append("udp large payload")
        s.close()
    except Exception as e:
        print(f"  [FAIL] UDP 大包异常: {e}")
        failures.append(f"udp large exception: {e}")

if __name__ == "__main__":
    test_tcp()
    time.sleep(0.3)
    test_udp()
    test_udp_large()
    print("\n========== 结果 ==========")
    if failures:
        print(f"失败 {len(failures)} 项:")
        for f in failures:
            print("  -", f)
        sys.exit(1)
    else:
        print("全部通过 ✅")
