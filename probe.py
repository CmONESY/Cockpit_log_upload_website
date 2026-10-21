# -*- coding: utf-8 -*-
"""探测宿主机上挂着哪个矿区的 VPN，以及驾舱是否在线。

判断 VPN 挂了没，用三条证据交叉验证：
  1) 正在运行的 openvpn 进程，cmdline 里的 .ovpn 文件名（最直接）
  2) 到该矿区驾舱 IP 的路由出口是不是 tun*/tap*（最能说明「真的能到」）
  3) tun/tap 设备的地址（辅助展示）

驾舱「在线」分三层，失败时能说清卡在哪一层：
  VPN 未挂载 → SSH 不可达 → 服务（IPC）异常 → 正常
"""

import os
import re
import socket
import subprocess


def _run(args, timeout=3.0):
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except Exception:  # noqa: BLE001 - 没装 ip/pgrep、容器里没 /proc 都走这里
        return -1, ""


def active_openvpn_configs():
    """当前正在运行的 openvpn 配置文件（读 /proc/*/cmdline）。"""
    found = []
    try:
        pids = os.listdir("/proc")
    except OSError:
        return found
    for pid in pids:
        if not pid.isdigit():
            continue
        try:
            with open("/proc/%s/cmdline" % pid, "rb") as handle:
                argv = [a.decode("utf-8", "replace") for a in handle.read().split(b"\0") if a]
        except OSError:
            continue
        if not argv or "openvpn" not in os.path.basename(argv[0]):
            continue
        for arg in argv:
            if arg.endswith(".ovpn") or arg.endswith(".conf"):
                found.append(arg)
    return sorted(set(found))


def tun_addresses():
    """{tun0: '10.8.0.6', ...}"""
    result = {}
    code, out = _run(["ip", "-o", "addr", "show"])
    if code != 0:
        return result
    for line in out.splitlines():
        # 普通网卡是 "inet 10.8.0.6/24"，点对点 tun 是 "inet 10.8.32.67 peer ..."
        match = re.match(r"\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)(?:/\d+)?", line)
        if match and match.group(1).startswith(("tun", "tap")):
            result[match.group(1)] = match.group(2)
    return result


def route_dev_for(host):
    """到某个 IP 会从哪张网卡出去。"""
    code, out = _run(["ip", "route", "get", host])
    if code != 0:
        return ""
    match = re.search(r"\bdev\s+(\S+)", out)
    return match.group(1) if match else ""


def tcp_check(host, port, timeout=2.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, ""
    except OSError as exc:
        return False, str(exc)


def detect_site_vpn(site_id, ovpn_hint, cockpit_hosts):
    """判断某个矿区的 VPN 是否挂着，以及能不能路由到它的驾舱。"""
    site_key = (site_id or "").lower()
    configs = active_openvpn_configs()
    matched = [path for path in configs
               if site_key and site_key in os.path.basename(path).lower()]
    if not matched and ovpn_hint:
        matched = [path for path in configs
                   if os.path.basename(path) == ovpn_hint]

    devs = {}
    for host in cockpit_hosts:
        dev = route_dev_for(host)
        if dev:
            devs[host] = dev
    tun_devs = sorted({dev for dev in devs.values()
                       if dev.startswith(("tun", "tap"))})

    # 关键：多个矿区的内网网段会重叠（比如西湾车辆和建龙 VPN 都覆盖 192.168.12.x），
    # 所以"路由走 tun0"不能证明这个矿区就是当前挂的那个——别的矿区的隧道也会把
    # 同样的网段推过来，甚至能连到那边的另一台机器。以正在运行的 .ovpn 为准。
    if configs:
        up = bool(matched)
        if up and cockpit_hosts and not tun_devs:
            # .ovpn 挂着，但到驾舱的路由没走隧道：多半是网段/路由不对
            up = False
    else:
        # 看不到 openvpn 进程（隧道由网关/别的环境提供）时，退回路由判断
        up = bool(tun_devs)
        if not cockpit_hosts and up:
            tun_devs = sorted(tun_addresses())

    parts = []
    if matched:
        parts.append("openvpn: " + ", ".join(os.path.basename(p) for p in matched))
    if tun_devs:
        addrs = tun_addresses()
        parts.append("隧道: " + ", ".join(
            "%s(%s)" % (dev, addrs[dev]) if dev in addrs else dev for dev in tun_devs))
    if devs and not tun_devs:
        parts.append("路由走了 " + ", ".join(sorted(set(devs.values()))))
    if tun_devs and not matched and configs:
        parts.append("该网段被其它矿区的隧道覆盖，当前未挂本矿区 VPN")

    return {
        "site": site_id,
        "up": up,
        "ovpn": os.path.basename(matched[0]) if matched else "",
        "iface": tun_devs[0] if tun_devs else "",
        "detail": "; ".join(parts) or "没有发现正在运行的 openvpn",
        "routes": devs,
    }
