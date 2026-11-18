#!/usr/bin/env bash
# watch-expiry.sh — 巡检已知原生组件目录，发现临近到期的截止时间锁
#
# 用法:
#   bash watch-expiry.sh                      # 扫描清单里的全部组件
#   bash watch-expiry.sh <单个dll>             # 只扫一个
#
# 判据来自 scan-expiry.js 的「边界时刻」启发式：
#   截止时刻落在 23:59:59 / 00:00:00 且靠近月末或年末 → 疑似人为设定
#
# 退出码:
#   0 = 未发现临近到期（>90 天）
#   1 = 发现 90 天内到期的组件，需要处理
#   2 = 用法错误

set -u

NODE="/d/app/node.exe"
SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCAN="$SKILL_DIR/scripts/scan-expiry.js"

# 受监控的组件清单：路径|说明
MANIFEST=(
  "D:/app/WeFlow/resources/resources/wcdb/win32/x64/wcdb_api.dll|WeFlow 5.0.0 主组件（曾于 2026-09-30 到期，已打补丁）"
  "D:/app/WeFlow/resources/resources/wcdb/win32/x64/WCDB.dll|WeFlow WCDB 引擎"
)

targets=()
if [ $# -ge 1 ]; then
  targets=("$@")
else
  for entry in "${MANIFEST[@]}"; do
    targets+=("${entry%%|*}")
  done
fi

[ -x "$NODE" ] || { echo "找不到 node: $NODE"; exit 2; }
[ -f "$SCAN" ] || { echo "找不到扫描脚本: $SCAN"; exit 2; }

echo "=== 原生组件到期巡检 $(date '+%Y-%m-%d %H:%M:%S') ==="
echo

found_soon=0
for t in "${targets[@]}"; do
  if [ ! -f "$t" ]; then
    echo "[跳过] 文件不存在: $t"
    continue
  fi

  sha=$(sha256sum "$t" 2>/dev/null | cut -d' ' -f1)
  echo "--- $t"
  echo "    SHA-256: $sha"

  out=$("$NODE" "$SCAN" "$t" 2>/dev/null)

  # 提取「高置信度」命中里的日期，判断是否 90 天内到期
  soon=$(echo "$out" | grep -oE '\(2[0-9]{3}-[0-9]{2}-[0-9]{2}T' | tr -d '(T' | while read -r d; do
    days=$(( ( $(date -d "$d" +%s) - $(date +%s) ) / 86400 ))
    if [ "$days" -ge 0 ] && [ "$days" -le 90 ]; then echo "$d (还剩 ${days} 天)"; fi
  done)

  if [ -n "$soon" ]; then
    found_soon=1
    echo "    ⚠ 临近到期:"
    echo "$soon" | sed 's/^/      /'
  else
    echo "    ✓ 无临近到期的检查点"
  fi
  echo
done

if [ "$found_soon" -eq 1 ]; then
  echo "结论: 发现 90 天内到期的组件，请用 patch-deadline.js 处理（参考 SKILL.md 的 Workflow）。"
  exit 1
fi

echo "结论: 全部组件无临近到期项。"
exit 0
