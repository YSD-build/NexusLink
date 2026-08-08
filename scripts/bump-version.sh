#!/bin/bash
# NexusLink 版本号一键升级脚本
# 用法: ./scripts/bump-version.sh v0.3.6 ["更新说明，可选"]
set -e
cd "$(dirname "$0")/.."
NEW="$1"
DESC="${2:-待补充}"
if [ -z "$NEW" ]; then
  echo "用法: $0 <新版本如 v0.3.6> [更新说明]"
  exit 1
fi
export NEW DESC
python3 - <<'PY'
import os, re
new = os.environ["NEW"]
desc = os.environ["DESC"]
old = re.search(r'var Version = "([^"]+)"', open("cmd/server/main.go", encoding="utf-8").read()).group(1)
if old == new:
    print(f"版本已是 {new}，无需升级")
    raise SystemExit(0)
print(f"版本升级: {old} -> {new}")

def rep(path, pairs):
    s = open(path, encoding="utf-8").read()
    for a, b in pairs:
        assert a in s, f"{path} 未匹配: {a}"
        s = s.replace(a, b, 1)
    open(path, "w", encoding="utf-8").write(s)
    print(f"  [OK] {path}")

rep("cmd/server/main.go", [(f'var Version = "{old}"', f'var Version = "{new}"')])
rep("cmd/client/main.go", [(f'var Version = "{old}"', f'var Version = "{new}"')])
rep("pkg/web/static/index.html", [(f'>{old}</span>', f'>{new}</span>'), (f"'{old}'", f"'{new}'")])
rep("scripts/install-nexuslink.sh", [(f'VERSION="{old}"', f'VERSION="{new}"')])

# README：当前版本段插入新行 + 资产名/链接/镜像标签替换（不动历史 changelog）
s = open("README.md", encoding="utf-8").read()
marker = "## 📌 当前版本\n"
head = s.split(marker, 1)[1].split("\n", 1)[0]
if f"**{new}**" not in head:
    s = s.replace(marker, marker + f"**{new}** — {desc}\n", 1)
s = s.replace(f"-{old}-", f"-{new}-")          # 资产名 nexuslink-server-v0.3.5-xxx
s = s.replace(f"/tag/{old}", f"/tag/{new}")
s = s.replace(f"/download/{old}/", f"/download/{new}/")
s = s.replace(f"web-panel-{old}.zip", f"web-panel-{new}.zip")
s = s.replace(f":{old[1:]}", f":{new[1:]}")     # 镜像标签 :0.3.5 -> :0.3.6
open("README.md", "w", encoding="utf-8").write(s)
print("  [OK] README.md")

print("版本引用升级完成。请检查 git diff 后执行：")
print("  git add -A && git commit -m \"release: " + new + " 版本号升级\"")
print("  git tag " + new + " && git push origin main --tags")
PY
