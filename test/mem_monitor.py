import time, sys

pid = int(sys.argv[1])
interval = float(sys.argv[2]) if len(sys.argv) > 2 else 0.5
out = sys.argv[3] if len(sys.argv) > 3 else 'mem.log'
start = time.time()
with open(out, 'w') as f:
    while True:
        try:
            with open(f'/proc/{pid}/status') as sf:
                for line in sf:
                    if line.startswith('VmRSS:'):
                        rss = int(line.split()[1])  # KB
                        break
            elapsed = time.time() - start
            f.write(f'{elapsed:.1f}\t{rss}\n')
            f.flush()
        except Exception:
            break
        time.sleep(interval)
