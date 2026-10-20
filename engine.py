# -*- coding: utf-8 -*-
"""驾舱通信引擎：把「按按钮」变成驾舱上的一次日志上报。

驾舱上的 rdc_log_upload 只监听 127.0.0.1:19726，从外部连不上，所以有两种传输：

  TcpTransport  直连 host:port —— 后端本身在驾舱上，或 ipc_bind 已放开时用
  SshTransport  走 SSH 的 direct-tcpip 通道，打到驾舱自己的 127.0.0.1:19726
                —— 生产环境走这条（后端在服务器，先拨矿区 VPN 再 SSH）

协议（一行 JSON 进、一行 JSON 出，服务端回完就关连接）：
    -> {"action":"ping"}          <- status=idle|uploading + progress
    -> {"action":"upload_today"}  <- status=started | busy | error
progress: phase=collecting|zipping|uploading|finishing|idle,
          kind=manual-today|scheduled-yesterday, percent, bytes_sent/total,
          object_key, started_at

注意：这个接口不报告任务成功与否（失败和成功都回 idle/100%），所以结论要靠
「观测到过哪些阶段」推断，或者在 OSS 侧核对对象。
"""

import json
import socket
import threading
import time
import re

import paramiko

PHASE_ORDER = {"idle": 0, "collecting": 1, "zipping": 2, "uploading": 3,
               "finishing": 4}
PHASE_TEXT = {"idle": "空闲", "collecting": "扫描日志", "zipping": "打包 ZIP",
              "uploading": "上传 OSS", "finishing": "收尾"}
KIND_TEXT = {"manual-today": "手动-当日", "scheduled-yesterday": "定时-昨日"}


class EngineError(RuntimeError):
    """连不上、认证失败之类，属于「这台车没打通」。"""


class IpcError(EngineError):
    """通道通了，但协议这一层出错。"""


def _read_one_json_line(recv, send, payload):
    """发一行 JSON、收回一行 JSON。recv/send 是 socket 或 paramiko channel。"""
    wire = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
    send(wire)
    buf = b""
    while b"\n" not in buf:
        block = recv(4096)
        if not block:
            break
        buf += block
        if len(buf) > 262144:
            break
    text = buf.decode("utf-8", "replace").strip()
    if not text:
        raise IpcError("驾舱没返回内容（服务在跑吗？端口对吗？）")
    try:
        return json.loads(text)
    except ValueError:
        raise IpcError("返回的不是 JSON：%r" % text[:200])


class TcpTransport:
    """直连模式：一次请求一条短连接。"""

    kind = "tcp"

    def __init__(self, host, port, connect_timeout=10.0, read_timeout=30.0):
        self.host = host
        self.port = port
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout

    def connect(self):
        return self

    def close(self):
        pass

    def request(self, payload):
        try:
            sock = socket.create_connection((self.host, self.port),
                                            timeout=self.connect_timeout)
        except OSError as exc:
            raise EngineError("连不上 %s:%d（%s）" % (self.host, self.port, exc))
        with sock:
            sock.settimeout(self.read_timeout)
            try:
                return _read_one_json_line(sock.recv, sock.sendall, payload)
            except socket.timeout:
                raise IpcError("等 %s:%d 回应超时" % (self.host, self.port))

    def run(self, command, timeout=20.0):
        raise IpcError("直连模式没法在驾舱上执行命令（只有 SSH 通道可以）")


class SshTransport:
    """SSH 通道模式：一条 SSH 连接，每次请求在上面开一条 direct-tcpip 通道。"""

    kind = "ssh"

    def __init__(self, host, user, password=None, key_filename=None,
                 ssh_port=22, ipc_host="127.0.0.1", ipc_port=19726,
                 connect_timeout=15.0, read_timeout=30.0):
        self.host = host
        self.user = user
        self.password = password
        self.key_filename = key_filename
        self.ssh_port = ssh_port
        self.ipc_host = ipc_host
        self.ipc_port = ipc_port
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.client = None
        self._lock = threading.Lock()

    @property
    def target(self):
        return "%s@%s" % (self.user, self.host)

    def connect(self):
        if self.client is not None:
            return self
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = dict(
            hostname=self.host, port=self.ssh_port, username=self.user,
            timeout=self.connect_timeout, banner_timeout=self.connect_timeout,
            auth_timeout=self.connect_timeout,
            # 只用显式给的那一种凭据：密码或指定私钥。
            # 否则 paramiko 会把 ~/.ssh 下和 agent 里的每把 key 都试一遍，
            # 每次失败都计入 sshd 的 MaxAuthTries，很容易被踢成
            # "Too many authentication failures" 甚至被限流。
            look_for_keys=False,
            allow_agent=False,
        )
        if self.password:
            kwargs["password"] = self.password
        if self.key_filename:
            kwargs["key_filename"] = self.key_filename
        try:
            client.connect(**kwargs)
        except paramiko.AuthenticationException as exc:
            raise EngineError("SSH 认证失败（用户名或密码不对）：%s" % exc)
        except paramiko.SSHException as exc:
            text = str(exc).lower()
            if "auth" in text:
                if not self.password and not self.key_filename:
                    raise EngineError(
                        "SSH 没拿到凭据：清单里 ssh_password_env 指向的环境变量没设？")
                raise EngineError("SSH 认证失败：%s" % exc)
            raise EngineError("SSH 连不上 %s:%d（%s）—— 矿区 VPN 通了吗？"
                              % (self.host, self.ssh_port, exc))
        except Exception as exc:  # noqa: BLE001
            text = str(exc).lower()
            if "reset by peer" in text:
                raise EngineError(
                    "驾舱 %s 重置了 SSH 连接：多半是之前登录失败次数过多触发的"
                    "临时封堵，等 15~30 分钟再试（或在驾舱上 Restart-Service sshd）"
                    % self.host)
            if "too many authentication" in text:
                raise EngineError(
                    "SSH 认证次数超限（%s）：客户端一次试了太多把密钥，等一会儿再试"
                    % self.host)
            if "timed out" in text or "no route" in text or "unreachable" in text:
                raise EngineError(
                    "SSH 连不上 %s:%d —— 矿区 VPN 通了吗？"
                    % (self.host, self.ssh_port))
            raise EngineError("SSH 连不上 %s:%d（%s）"
                              % (self.host, self.ssh_port, exc))
        self.client = client
        return self

    def close(self):
        if self.client is not None:
            try:
                self.client.close()
            finally:
                self.client = None

    def _transport(self):
        self.connect()
        transport = self.client.get_transport()
        if transport is None or not transport.is_active():
            self.client = None
            self.connect()
            transport = self.client.get_transport()
        return transport

    def request(self, payload):
        transport = self._transport()
        try:
            channel = transport.open_channel(
                "direct-tcpip", (self.ipc_host, self.ipc_port), ("127.0.0.1", 0),
                timeout=self.connect_timeout)
        except paramiko.ChannelException as exc:
            raise IpcError(
                "驾舱拒绝端口转发（%s）：可能是 sshd 关了 AllowTcpForwarding，"
                "或者那台驾舱上服务没在跑。" % exc)
        except Exception as exc:  # noqa: BLE001
            raise IpcError("开通道失败：%s" % exc)
        try:
            channel.settimeout(self.read_timeout)
            return _read_one_json_line(channel.recv, channel.sendall, payload)
        except IpcError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise IpcError("收发失败：%s" % exc)
        finally:
            try:
                channel.close()
            except Exception:  # noqa: BLE001
                pass

    def run(self, command, timeout=20.0):
        """在驾舱上跑一条命令（用来读配置、查服务状态）。Windows 下走 cmd。"""
        self.connect()
        with self._lock:
            _, stdout, _ = self.client.exec_command(command, timeout=timeout)
            out = stdout.read().decode("utf-8", "replace")
            code = stdout.channel.recv_exit_status()
        return code, out


def make_transport(cockpit):
    """按清单里那条记录建传输层。"""
    kind = (cockpit.get("transport") or "ssh").lower()
    if kind == "tcp":
        return TcpTransport(cockpit["host"], int(cockpit.get("ipc_port", 19726)))
    return SshTransport(
        host=cockpit["host"],
        user=cockpit.get("ssh_user") or "breton",
        password=cockpit.get("ssh_password"),
        key_filename=cockpit.get("ssh_key"),
        ssh_port=int(cockpit.get("ssh_port", 22)),
        ipc_port=int(cockpit.get("ipc_port", 19726)),
    )


def progress_of(resp):
    progress = resp.get("progress")
    return progress if isinstance(progress, dict) else {}


def describe(progress):
    """一行文字摘要（后端日志/调试用；网页上是前端自己排版）。"""
    phase = progress.get("phase") or "idle"
    parts = [PHASE_TEXT.get(phase, phase), "%d%%" % int(progress.get("percent") or 0)]
    total = progress.get("bytes_total") or 0
    if phase == "uploading" and total:
        parts.append("%.1f/%.1f MiB" % (float(progress.get("bytes_sent") or 0) / 1048576,
                                        float(total) / 1048576))
    if progress.get("object_key"):
        parts.append(progress["object_key"])
    kind = progress.get("kind") or ""
    if kind:
        parts.append("[%s]" % KIND_TEXT.get(kind, kind))
    return " ".join(parts)


def verdict(best_phase, latest):
    """只靠 IPC 能给出的结论：success / failed / unknown。"""
    object_key = (latest or {}).get("object_key") or ""
    if best_phase == "finishing":
        return "success", "观测到收尾阶段，S3 已返回成功"
    if not object_key:
        return "failed", "任务结束但没进到上传阶段，多半卡在扫描或打包"
    if best_phase == "uploading":
        return "unknown", "进过上传阶段但没观测到收尾，接口不报结果，需查 OSS"
    return "unknown", "任务很快结束，没观测到上传和收尾，需查 OSS"


def follow(transport, on_update, poll_interval=1.0, overall_timeout=1800,
           busy_grace=3.0):
    """轮询到任务结束。返回 (最高阶段, 最后一次 progress, 是否超时)。

    刚开始可能还没切到 uploading（甚至一瞬 idle），所以给个宽限期：只有在
    「确实看到了任务」之后，第一次出现 idle 才算结束。
    """
    best = "idle"
    latest = None
    started = time.monotonic()
    deadline = None if overall_timeout <= 0 else started + overall_timeout
    seen_busy = False
    while True:
        resp = transport.request({"action": "ping"})
        progress = progress_of(resp)
        phase = progress.get("phase") or "idle"
        if PHASE_ORDER.get(phase, 0) > PHASE_ORDER.get(best, 0):
            best = phase
        latest = progress
        elapsed = time.monotonic() - started
        if resp.get("status") != "idle":
            seen_busy = True
        on_update(phase, progress, elapsed)
        if resp.get("status") == "idle" and phase == "idle":
            if seen_busy or elapsed >= busy_grace:
                return best, latest, False
        if deadline is not None and time.monotonic() > deadline:
            return best, latest, True
        time.sleep(poll_interval)


def probe(transport):
    """体检：装没装、服务在不在跑、是哪个驾舱编号、配置和目录在哪。"""
    result = {"transport": transport.kind}
    code, out = transport.run("hostname")
    result["hostname"] = out.strip() if code == 0 else ""
    code, out = transport.run("sc query rdc_log_upload")
    upper = out.upper()
    result["service_installed"] = ("RUNNING" in upper) or ("STOPPED" in upper)
    result["service_running"] = "RUNNING" in upper
    code, out = transport.run("sc qc rdc_log_upload")
    exe_path = ""
    for line in out.splitlines():
        if "BINARY_PATH_NAME" in line.upper():
            exe_path = line.split(":", 1)[-1].strip().strip('"')
    result["exe_path"] = exe_path
    if exe_path:
        cfg = exe_path.replace("/", "\\").rsplit("\\", 1)[0] + "\\rdc_log_upload.json"
        result["config_path"] = cfg
        code, out = transport.run('type "%s"' % cfg)
        try:
            cfg_json = json.loads(out[out.index("{"):])
            for key in ("service_type", "ipc_port", "ipc_bind", "work_dir",
                        "service_log_dir", "log_dirs", "schedule_time"):
                result[key] = cfg_json.get(key)
            result["key_prefix"] = (cfg_json.get("oss") or {}).get("key_prefix")
        except ValueError:
            result["config_parse_error"] = True
    return result


def _run_quiet(transport, command, timeout=20.0):
    try:
        return transport.run(command, timeout=timeout)
    except Exception:  # noqa: BLE001 - 直连模式没有 run()
        return -1, ""


def discover_layout(transport):
    """找到驾舱上服务的配置文件 / 工作目录 / 驾舱编号（Windows 服务或 Linux 进程都认）."""
    code, out = _run_quiet(transport, "sc qc rdc_log_upload")
    exe_path = ""
    for line in out.splitlines():
        if "BINARY_PATH_NAME" in line.upper():
            exe_path = line.split(":", 1)[-1].strip().strip('"')
    is_windows = bool(exe_path) or ".exe" in out.lower() or "\\" in out

    config_path = ""
    match = re.search(r'--config\s+"([^"]+)"', out)
    if match:
        config_path = match.group(1)
    if not config_path and exe_path and "\\" in exe_path:
        config_path = exe_path.rsplit("\\", 1)[0] + "\\rdc_log_upload.json"
    if not config_path:
        code, text = _run_quiet(transport, "pgrep -af rdc_log_upload")
        match = re.search(r"--config\s+(\S+)", text)
        if match:
            config_path = match.group(1)
    if not config_path:
        return None

    cmd = ('type "%s"' % config_path) if is_windows else ("cat '%s'" % config_path)
    code, text = _run_quiet(transport, cmd)
    if "{" not in text:
        return None
    try:
        cfg = json.loads(text[text.index("{"):])
    except ValueError:
        return None
    return {
        "is_windows": is_windows,
        "exe_path": exe_path,
        "config_path": config_path,
        "work_dir": cfg.get("work_dir") or "",
        "service_log_dir": cfg.get("service_log_dir") or "",
        "service_type": cfg.get("service_type") or "",
        "ipc_port": cfg.get("ipc_port"),
        "log_dirs": cfg.get("log_dirs") or [],
        "schedule_time": cfg.get("schedule_time") or "",
    }


def read_last_upload(transport, layout):
    """读驾舱 work/state.json 里最新一条上传记录（只有成功才会写）。"""
    work_dir = ((layout or {}).get("work_dir") or "").rstrip("\\/")
    if not work_dir:
        return None
    if layout.get("is_windows"):
        command = 'type "%s\\state.json"' % work_dir
    else:
        command = "cat '%s/state.json'" % work_dir
    code, text = _run_quiet(transport, command)
    if "{" not in text:
        return None
    try:
        data = json.loads(text[text.index("{"):])
    except ValueError:
        return None
    uploads = data.get("uploads") or []
    record = uploads[0] if uploads else data.get("last_upload")
    return record if isinstance(record, dict) else None


def record_marker(record):
    if not record:
        return None
    return (record.get("uploaded_at"), record.get("object_key"))
