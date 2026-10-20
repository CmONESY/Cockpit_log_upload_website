#!/bin/bash
# 把网站装成当前用户的 systemd 服务：开机/登录后自动跑，崩了自动重启。
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
mkdir -p "$UNIT_DIR"
install -m 644 "$HERE/rdc-log-web.service" "$UNIT_DIR/rdc-log-web.service"

export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
systemctl --user daemon-reload
systemctl --user enable --now rdc-log-web.service
systemctl --user --no-pager status rdc-log-web.service | head -12

echo
echo "局域网地址：$(hostname -I | awk '{print $1}'):8080"
echo "查看日志： journalctl --user -u rdc-log-web -f"
echo "停止服务： systemctl --user stop rdc-log-web"
