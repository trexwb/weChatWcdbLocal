#!/usr/bin/env bash
#
# resign-wechat.sh —— 为 macOS「无需 sudo」抓微信密钥铺路（只做一件事：生成重签名副本）。
#
# 背景：frida / lldb 要读微信内存，需要目标进程带 com.apple.security.get-task-allow。
#      App Store 原版微信是 Hardened Runtime 签名且没有该授权，SIP 开启下 task_for_pid 必然被拒，
#      提权也解不开。破局方式是复制一份副本并 ad-hoc 重签名、把 get-task-allow 加上
#      （同时保留 app-sandbox，否则微信会切到另一个数据目录、读不到已有记录）。
#      此后目标进程属主是你本人、又带 get-task-allow，同用户非 root 即可 attach。
#
# 安全边界（务必理解）：
#   * 全程不需要 sudo，也不允许用 sudo / root 运行（脚本会直接拒绝）：root 复制出来的副本
#     属主是 root，与当前用户不一致，反而又得提权，白做。
#   * 只写副本 ~/Applications/WeChat.app，绝不改动 /Applications/WeChat.app 原版。
#   * 副本已存在时默认退出；要重建请显式加 --force，旧副本会先被【改名】为
#     WeChat.app.bak-<时间戳> 保留，脚本内不做任何 rm -rf。
#
# 用法:
#   bash scripts/resign-wechat.sh            # 首次创建副本（已存在则退出）
#   bash scripts/resign-wechat.sh --force    # 重建副本（旧副本改名为带时间戳的备份）

set -euo pipefail

SRC="/Applications/WeChat.app"
DEST_DIR="$HOME/Applications"
DEST="$DEST_DIR/WeChat.app"
STAMP="$(date +%Y%m%d-%H%M%S)"

FORCE=0
for arg in "$@"; do
  case "$arg" in
    --force | -f) FORCE=1 ;;
    -h | --help)
      cat <<'USAGE'
用法:
  bash scripts/resign-wechat.sh            # 首次创建副本（副本已存在时退出）
  bash scripts/resign-wechat.sh --force    # 重建副本（旧副本改名为带时间戳的备份）

作用: 把 /Applications/WeChat.app 复制到 ~/Applications/WeChat.app 并 ad-hoc 重签名，
      加上 com.apple.security.get-task-allow、保留 com.apple.security.app-sandbox，
      删除 application-identifier / team-identifier。全程不需要 sudo，只动副本。
USAGE
      exit 0
      ;;
    *)
      echo "未知参数：$arg（可用：--force）" >&2
      exit 2
      ;;
  esac
done

# 必须有这道闸：root 下复制会让副本属主变成 root，属主不一致就又需要提权了
if [ "$(id -u)" -eq 0 ]; then
  echo "不要用 sudo / root 运行本脚本：副本必须属于你自己。" >&2
  echo "请直接用普通用户执行：bash scripts/resign-wechat.sh" >&2
  exit 1
fi

if [ ! -d "$SRC" ]; then
  echo "找不到 $SRC，请确认微信已安装在 /Applications。" >&2
  exit 1
fi

mkdir -p "$DEST_DIR"

if [ -e "$DEST" ]; then
  if [ "$FORCE" -ne 1 ]; then
    echo "副本已存在：$DEST"
    echo "如需重建，请显式加 --force（旧副本会先改名为 $DEST.bak-$STAMP 保留，不会被删除）。"
    exit 1
  fi
  echo "已存在副本，先改名为备份（不删除）：$DEST.bak-$STAMP"
  mv "$DEST" "$DEST.bak-$STAMP"
fi

# 先在临时位置完成「复制 -> 改授权 -> 重签名 -> 校验」，全部通过后再改名就位；
# 中途失败也不会留下一个「看起来能用」的半成品副本。
TMP_APP="$DEST_DIR/.WeChat.app.resigning-$STAMP"
ENT_PLIST="$DEST_DIR/WeChat.app.entitlements-$STAMP.plist"

cleanup_failed() {
  if [ -e "$TMP_APP" ]; then
    mv "$TMP_APP" "$TMP_APP.failed-$STAMP" 2>/dev/null || true
    echo "未完成的副本已改名为：$TMP_APP.failed-$STAMP（未删除，可自行检查后处理）" >&2
  fi
}

fail() {
  echo "$1" >&2
  cleanup_failed
  exit 1
}

trap cleanup_failed ERR

echo "1/5 复制 $SRC -> $TMP_APP（ditto，保留签名与资源分支）"
ditto "$SRC" "$TMP_APP"

echo "2/5 导出原版授权"
# codesign 在不同版本里可能把 plist 写到 stdout 或 stderr，两种都兜住
codesign -d --entitlements :- "$SRC" >"$ENT_PLIST" 2>/dev/null || true
if ! grep -q '<plist' "$ENT_PLIST" 2>/dev/null; then
  codesign -d --entitlements :- "$SRC" >"$ENT_PLIST" 2>&1 || true
fi
if ! grep -q '<plist' "$ENT_PLIST" 2>/dev/null; then
  fail "导出授权失败（$ENT_PLIST 里没有 plist 内容）。可先手工确认：codesign -d --entitlements :- $SRC"
fi

echo "3/5 改授权：加 get-task-allow、保留 app-sandbox、删 application-identifier / team-identifier"
PB=/usr/libexec/PlistBuddy
$PB -c "Set :com.apple.security.get-task-allow true" "$ENT_PLIST" 2>/dev/null ||
  $PB -c "Add :com.apple.security.get-task-allow bool true" "$ENT_PLIST"
$PB -c "Set :com.apple.security.app-sandbox true" "$ENT_PLIST" 2>/dev/null ||
  $PB -c "Add :com.apple.security.app-sandbox bool true" "$ENT_PLIST"
# 这两个是原始签发信息（TeamID 声明），ad-hoc 重签名时必须去掉
for key in application-identifier developer.team-identifier com.apple.developer.team-identifier; do
  $PB -c "Delete :$key" "$ENT_PLIST" 2>/dev/null || true
done

echo "4/5 ad-hoc 重签名（只签副本，原版不碰）"
codesign --force --deep --sign - --entitlements "$ENT_PLIST" "$TMP_APP"

echo "5/5 校验"
EF="$(codesign -d --entitlements :- "$TMP_APP" 2>&1 || true)"
case "$EF" in
  *com.apple.security.get-task-allow*) ;;
  *) fail "校验失败：重签名后的副本没有 get-task-allow。" ;;
esac
case "$EF" in
  *com.apple.security.app-sandbox*) ;;
  *) fail "校验失败：重签名后的副本丢了 app-sandbox（微信会切数据目录）。" ;;
esac
if ! codesign --verify --deep "$TMP_APP" >/dev/null 2>&1; then
  echo "提示：codesign --verify --deep 未通过（ad-hoc 签名下通常仍可运行），继续。" >&2
fi

mv "$TMP_APP" "$DEST"
trap - ERR

echo
echo "完成。重签名副本：$DEST"
echo "（原版 $SRC 未被修改：本脚本从未对它执行任何写操作。）"
echo "本次使用的授权文件已保留供核对：$ENT_PLIST"
echo
echo "下一步（全程不需要 sudo）："
echo "  1) 完全退出原版微信（含菜单栏图标），再从 $DEST 启动微信并登录；"
echo "  2) 在项目目录运行：node bin/wcdb.js key --mac-frida -o keys.json"
echo "     （先运行命令，再在 90 秒内启动微信；首次被拒时到「系统设置 → 隐私与安全性 → 开发者工具」为终端授权）"
echo "  3) 之后：node bin/wcdb.js decrypt --keys keys.json --out plain/"
echo
echo "备注：ad-hoc 签名不被 Gatekeeper 认可（spctl 会拒绝），但本地拷贝没有 quarantine 属性，"
echo "     正常启动不受影响；若被拦，右键 → 打开 一次即可。"
