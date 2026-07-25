#!/usr/bin/env bash
# NexusLink 严格攻击韧性测试运行器（干净启动 + 就绪校验 + 测试 + 清理）
set -u
cd "$(dirname "$0")/.."            # NexusLink 根目录
ROOT="$(pwd)"
BIN="$ROOT/bin"
TEST="$ROOT/test"

ATTACK_DUR="${1:-30}"

echo "[run] === 清理旧进程 ==="
pkill -f 'bin/nexuslink-server' 2>/dev/null || true
pkill -f 'bin/nexuslink-client' 2>/dev/null || true
pkill -f 'echo_server.py' 2>/dev/null || true
pkill -f 'echo_udp_server.py' 2>/dev/null || true
pkill -f 'attack_test.py' 2>/dev/null || true
sleep 1

echo "[run] === 重新编译 server + client ==="
( cd "$ROOT" && go build -o "$BIN/nexuslink-server" ./cmd/server/ && go build -o "$BIN/nexuslink-client" ./cmd/client/ ) \
  || { echo "[run] BUILD FAIL"; exit 1; }
echo "[run] 编译完成"

echo "[run] === 启动回显服务 (TCP:9000 / UDP:9001) ==="
python3 "$TEST/echo_server.py" > "$TEST/echo_tcp.log" 2>&1 &
echo $! > "$TEST/.echo_tcp.pid"
python3 "$TEST/echo_udp_server.py" > "$TEST/echo_udp.log" 2>&1 &
echo $! > "$TEST/.echo_udp.pid"
sleep 1

echo "[run] === 启动服务端 (127.0.0.1:7000, web:7001) ==="
"$BIN/nexuslink-server" -c "$TEST/server.yaml" > "$TEST/server_run.log" 2>&1 &
echo $! > "$TEST/.server.pid"
sleep 2

echo "[run] === 启动客户端 (注册 echo/echo_udp 隧道) ==="
"$BIN/nexuslink-client" -c "$TEST/client.yaml" > "$TEST/client_run.log" 2>&1 &
echo $! > "$TEST/.client.pid"

echo "[run] === 等待隧道端口就绪 (25565 TCP / 25566 UDP 回显验证) ==="
python3 - "$ATTACK_DUR" <<'PY'
import socket, time, sys
dur = int(sys.argv[1])
def tcp_ok():
    try:
        s = socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', 25565))
        s.sendall(b'ping'); return s.recv(4096) == b'ping'
    except Exception:
        return False
    finally:
        try: s.close()
        except Exception: pass
def udp_ok():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1)
        s.sendto(b'ping', ('127.0.0.1', 25566))
        return s.recvfrom(65535)[0] == b'ping'
    except Exception:
        return False
    finally:
        try: s.close()
        except Exception: pass
t = u = False
for i in range(30):
    if not t: t = tcp_ok()
    if not u: u = udp_ok()
    if t and u:
        print(f"[run] 隧道就绪 (TCP+UDP echo 验证通过, 第{i+1}次轮询)"); break
    time.sleep(1)
if not (t and u):
    print(f"[run] !! 隧道未就绪 TCP={t} UDP={u} —— 中止测试")
    sys.exit(2)
PY
[ $? -ne 0 ] && { echo "[run] 就绪校验失败"; kill $(cat "$TEST/.server.pid" "$TEST/.client.pid" "$TEST/.echo_tcp.pid" "$TEST/.echo_udp.pid") 2>/dev/null; exit 2; }

echo "[run] === 发动全攻击面并实时监测 (attack_dur=${ATTACK_DUR}s) ==="
python3 "$TEST/attack_test.py" "$ATTACK_DUR" 2>&1 | tee "$TEST/attack_out.log"
RC=${PIPESTATUS[0]}

echo "[run] === 测试结束 (exit=$RC)，清理进程 ==="
for f in .server.pid .client.pid .echo_tcp.pid .echo_udp.pid; do
  [ -f "$TEST/$f" ] && { kill "$(cat "$TEST/$f")" 2>/dev/null; rm -f "$TEST/$f"; }
done
pkill -f 'attack_test.py' 2>/dev/null || true
echo "[run] 清理完成。结果见 $TEST/attack_out.log / server_run.log / client_run.log"
exit $RC
