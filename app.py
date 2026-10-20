# -*- coding: utf-8 -*-
"""驾舱日志上报控制台 —— 后端。

网页点一下「触发上传」，后端就：
    按矿区拨 VPN（宿主机/容器负责）→ SSH 到驾舱 → 开通道到 127.0.0.1:19726
    → 发 {"action":"upload_today"} → 每秒 {"action":"ping"} → 把进度推给浏览器

浏览器只管点按钮和看进度（SSE 实时推送），自己不碰驾舱。

启动：
    cd webapp && python3 app.py            # 默认 0.0.0.0:8080
    PORT=9000 python3 app.py
"""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import urllib.parse
import uuid
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import (FileResponse, JSONResponse, PlainTextResponse,
                               RedirectResponse, Response, StreamingResponse)

import engine
import probe

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.environ.get("COCKPITS_CONFIG", os.path.join(HERE, "cockpits.json"))
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", "1.0"))
JOB_TIMEOUT = float(os.environ.get("JOB_TIMEOUT", "1800"))
# VPN 状态变化要快（15s 一探）；但 TCP 探测驾舱端口要慢（60s 一次），
# 高频连接 22 端口在对方的安全设备眼里很像端口扫描。
HEALTH_INTERVAL = float(os.environ.get("HEALTH_INTERVAL", "15"))
HEALTH_TCP_INTERVAL = float(os.environ.get("HEALTH_TCP_INTERVAL", "60"))
_last_tcp_scan = [0.0]


def load_dotenv():
    """读 webapp/.env（KEY=VALUE），不覆盖已有环境变量。密码不进仓库。"""
    path = os.path.join(HERE, ".env")
    if not os.path.isfile(path):
        return
    with open(path, "r", encoding="utf-8-sig") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_dotenv()


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8-sig") as handle:
        cfg = json.load(handle)
    # 密码不写进配置文件，从环境变量取（配置里写 ssh_password_env 指向变量名）
    for cockpit in cfg.get("cockpits", []):
        env_name = cockpit.get("ssh_password_env")
        if env_name and not cockpit.get("ssh_password"):
            cockpit["ssh_password"] = os.environ.get(env_name, "")
    return cfg


CONFIG = load_config()
SITES = {s["id"]: s for s in CONFIG.get("sites", [])}
COCKPITS = {c["id"]: c for c in CONFIG.get("cockpits", [])}
UPLOAD_CONCURRENCY = int(CONFIG.get("upload_concurrency", 5))

LOCK = threading.Lock()
BATCHES = {}
UPLOAD_SLOTS = threading.Semaphore(UPLOAD_CONCURRENCY)
HEALTH_LOCK = threading.Lock()
SITE_HEALTH = {}       # site_id -> probe.detect_site_vpn() 的结果
COCKPIT_HEALTH = {}    # cockpit_id -> {vpn, ssh, ipc, checked_at, ...}
LAYOUT_CACHE = {}      # cockpit_id -> (layout, ts)
LAYOUT_TTL = 600.0

@asynccontextmanager
async def lifespan(_app):
    threading.Thread(target=health_loop, daemon=True).start()
    yield


app = FastAPI(title="驾舱日志上报控制台", lifespan=lifespan)


def parse_users():
    """账号来源：APP_USERS="alice:pass,bob:pass" 优先，否则退回 APP_USER/APP_PASSWORD。"""
    users = {}
    raw = os.environ.get("APP_USERS", "").strip()
    if raw:
        for item in raw.split(","):
            item = item.strip()
            if not item or ":" not in item:
                continue
            name, _, password = item.partition(":")
            if name.strip() and password.strip():
                users[name.strip()] = password.strip()
    if not users:
        password = os.environ.get("APP_PASSWORD", "")
        if password:
            users[os.environ.get("APP_USER", "admin")] = password
    return users


APP_USERS = parse_users()
APP_SECRET = os.environ.get("APP_SECRET") or hashlib.sha256(
    ("rdc|" + "|".join("%s=%s" % item for item in sorted(APP_USERS.items())))
    .encode("utf-8")).hexdigest()
AUDIT_PATH = os.path.join(HERE, "data", "audit.jsonl")
AUDIT_LOCK = threading.Lock()


def audit(**fields):
    """追加一条操作记录，供页面展示 / 事后追责。"""
    fields["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    try:
        os.makedirs(os.path.dirname(AUDIT_PATH), exist_ok=True)
        with AUDIT_LOCK:
            with open(AUDIT_PATH, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(fields, ensure_ascii=False) + "\n")
    except OSError:
        pass


def make_token(user):
    expiry = int(time.time()) + 7 * 86400
    raw = "%s|%d" % (user, expiry)
    sig = hmac.new(APP_SECRET.encode("utf-8"), raw.encode("utf-8"),
                   hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(("%s|%s" % (raw, sig)).encode("utf-8")).decode()


def check_token(token):
    if not token:
        return None
    try:
        raw = base64.urlsafe_b64decode(token.encode("utf-8")).decode("utf-8")
        user, expiry, sig = raw.split("|")
        expected = hmac.new(APP_SECRET.encode("utf-8"),
                            ("%s|%s" % (user, expiry)).encode("utf-8"),
                            hashlib.sha256).hexdigest()
        if hmac.compare_digest(sig, expected) and int(expiry) > time.time():
            return user
    except Exception:  # noqa: BLE001
        return None
    return None


def check_basic(header):
    if not header.startswith("Basic "):
        return None
    try:
        user, _, password = base64.b64decode(header[6:]).decode("utf-8").partition(":")
    except Exception:  # noqa: BLE001
        return None
    expected = APP_USERS.get(user)
    if expected and secrets.compare_digest(password, expected):
        return user
    return None


OPEN_PATHS = ("/login", "/logout", "/healthz", "/favicon.ico")


@app.middleware("http")
async def auth_gate(request, call_next):
    """登录页面 + Cookie（浏览器），同时保留 Basic（curl/脚本）。

    这个页面能触发生产驾舱上传，不能裸奔。没有配置账号时不拦截（仅限本机调试）。
    """
    if not APP_USERS:
        return await call_next(request)
    path = request.url.path
    if path in OPEN_PATHS or path.startswith("/static/"):
        return await call_next(request)
    user = check_token(request.cookies.get("rdc_user", ""))
    if not user:
        user = check_basic(request.headers.get("authorization", ""))
    if user:
        request.state.user = user
        return await call_next(request)
    if path.startswith("/api/"):
        return JSONResponse({"error": "需要登录"}, status_code=401)
    return RedirectResponse("/login", status_code=303)


LOGIN_PAGE = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>登录 · 驾舱日志上报控制台</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
     background:#f6f7f9;font:14px/1.6 "Segoe UI","Microsoft YaHei",system-ui,sans-serif;color:#1f2329}
.card{width:340px;background:#fff;border:1px solid #e3e6ea;border-radius:12px;
      padding:26px 24px;box-shadow:0 8px 24px rgba(0,0,0,.06)}
h1{margin:0 0 4px;font-size:18px}
p.sub{margin:0 0 18px;color:#6b7280;font-size:12.5px}
label{display:block;font-size:12.5px;color:#6b7280;margin:12px 0 4px}
input{width:100%;box-sizing:border-box;padding:9px 11px;border:1px solid #d7dbe0;
      border-radius:7px;font:inherit}
button{width:100%;margin-top:18px;padding:10px;border:0;border-radius:7px;
       background:#2563eb;color:#fff;font:inherit;cursor:pointer}
button:hover{background:#1d4ed8}
.err{margin-top:12px;padding:8px 10px;border-radius:7px;background:#fef2f2;
     color:#b91c1c;font-size:12.5px}
</style></head><body>
<form class="card" method="post" action="/login">
  <h1>驾舱日志上报控制台</h1>
  <p class="sub">请使用分配给你的账号登录</p>
  <label>用户名</label>
  <input name="username" autocomplete="username" autofocus>
  <label>密码</label>
  <input name="password" type="password" autocomplete="current-password">
  <button type="submit">登录</button>
  {error}
</form>
</body></html>"""


@app.get("/login")
def login_page():
    return Response(LOGIN_PAGE.replace("{error}", ""),
                    media_type="text/html; charset=utf-8")


@app.post("/login")
async def login_submit(request: Request):
    raw = (await request.body()).decode("utf-8", "replace")
    form = urllib.parse.parse_qs(raw)
    user = (form.get("username") or [""])[0].strip()
    password = (form.get("password") or [""])[0]
    expected = APP_USERS.get(user)
    if expected and secrets.compare_digest(password, expected):
        response = RedirectResponse("/", status_code=303)
        response.set_cookie("rdc_user", make_token(user), max_age=7 * 86400,
                            httponly=True, samesite="lax", path="/")
        audit(event="login", user=user,
              ip=(request.client.host if request.client else ""))
        return response
    return Response(
        LOGIN_PAGE.replace("{error}", '<div class="err">用户名或密码不对</div>'),
        status_code=401, media_type="text/html; charset=utf-8")


@app.get("/logout")
def logout():
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie("rdc_user", path="/")
    return response


def public_cockpit(cockpit):
    return {
        "id": cockpit["id"],
        "name": cockpit.get("name") or cockpit["id"],
        "site": cockpit.get("site", ""),
        "site_name": (SITES.get(cockpit.get("site", "")) or {}).get("name")
                     or cockpit.get("site", ""),
        "host": cockpit["host"],
        "transport": cockpit.get("transport", "ssh"),
        "ssh_user": cockpit.get("ssh_user", ""),
        "ipc_port": cockpit.get("ipc_port", 19726),
        "note": cockpit.get("note", ""),
    }


def make_job(cockpit, action):
    return {
        "cockpit_id": cockpit["id"],
        "name": cockpit.get("name") or cockpit["id"],
        "site": cockpit.get("site", ""),
        "host": cockpit["host"],
        "action": action,
        "state": "queued",        # queued|connecting|running|done|failed
        "phase": "",
        "percent": 0,
        "bytes_sent": 0,
        "bytes_total": 0,
        "kind": "",
        "object_key": "",
        "reached_phase": "",
        "verdict": "",            # success|unknown|failed|unreachable|""
        "message": "排队中",
        "last_upload": None,      # 驾舱 state.json 里最新一条成功记录
        "started_at": None,
        "finished_at": None,
        "elapsed": 0.0,
        "updated_at": time.time(),
    }


def set_job(job, **fields):
    with LOCK:
        job.update(fields)
        job["updated_at"] = time.time()


def mark_health(cockpit_id, **fields):
    with HEALTH_LOCK:
        entry = COCKPIT_HEALTH.setdefault(cockpit_id, {})
        entry.update(fields)
        entry["checked_at"] = time.time()


def get_layout(cockpit, transport):
    """服务在驾舱上的安装布局（配置/工作目录/编号），缓存 10 分钟。"""
    now = time.time()
    with LOCK:
        cached = LAYOUT_CACHE.get(cockpit["id"])
    if cached and now - cached[1] < LAYOUT_TTL:
        return cached[0]
    layout = engine.discover_layout(transport)
    if layout:
        with LOCK:
            LAYOUT_CACHE[cockpit["id"]] = (layout, now)
    return layout


def health_scan(force_tcp=False):
    """扫一遍：每个矿区 VPN 挂没挂 + 每台驾舱的 SSH 通不通。"""
    hosts_by_site = {}
    for cockpit in COCKPITS.values():
        hosts_by_site.setdefault(cockpit.get("site", ""), []).append(cockpit["host"])

    for site in CONFIG.get("sites", []):
        info = probe.detect_site_vpn(site["id"], site.get("vpn", ""),
                                     hosts_by_site.get(site["id"], []))
        with HEALTH_LOCK:
            SITE_HEALTH[site["id"]] = info

    do_tcp = force_tcp or (time.monotonic() - _last_tcp_scan[0] >= HEALTH_TCP_INTERVAL)
    if do_tcp:
        _last_tcp_scan[0] = time.monotonic()

    def check_one(cockpit):
        transport_kind = (cockpit.get("transport") or "ssh").lower()
        site_up = (SITE_HEALTH.get(cockpit.get("site", "")) or {}).get("up", False)
        base = {"vpn": "n/a" if transport_kind == "tcp"
                        else ("up" if site_up else "down")}
        if not do_tcp:
            # 本轮不做 TCP 探测，只更新 VPN 维度，保留上次的连接结论
            with HEALTH_LOCK:
                prev = dict(COCKPIT_HEALTH.get(cockpit["id"], {}))
            for key in ("ssh", "ssh_error", "ipc", "ipc_message"):
                if key in prev:
                    base[key] = prev[key]
            mark_health(cockpit["id"], **base)
            return

        if transport_kind == "tcp":
            # 直连模式不依赖矿区 VPN，直接探一下 IPC 端口
            ok, err = probe.tcp_check(cockpit["host"],
                                      int(cockpit.get("ipc_port", 19726)), timeout=1.5)
            fields = {"vpn": "n/a", "ssh": "n/a",
                      "ipc": "ok" if ok else "fail",
                      "ipc_message": "" if ok else err}
            mark_health(cockpit["id"], **fields)
            return
        fields = dict(base)
        if not site_up:
            fields.update({"ssh": "unknown", "ssh_error": "矿区 VPN 未挂载"})
            mark_health(cockpit["id"], **fields)
            return
        ok, err = probe.tcp_check(cockpit["host"],
                                  int(cockpit.get("ssh_port", 22)), timeout=2.5)
        fields.update({"ssh": "ok" if ok else "fail", "ssh_error": "" if ok else err})
        mark_health(cockpit["id"], **fields)

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(check_one, list(COCKPITS.values())))


def health_loop():
    while True:
        try:
            health_scan()
        except Exception:  # noqa: BLE001 - 探测失败不能把服务带崩
            pass
        time.sleep(max(5.0, HEALTH_INTERVAL))


def run_job(job, cockpit, action, use_slot, user=""):
    if use_slot:
        set_job(job, message="排队中（等待并发名额）")
        UPLOAD_SLOTS.acquire()
    set_job(job, state="connecting", started_at=time.time(), message="建立通道…")
    transport = None
    try:
        transport = engine.make_transport(cockpit)
        transport.connect()
        mark_health(cockpit["id"], ssh="ok", ssh_error="", vpn="up")
        layout = get_layout(cockpit, transport)
        if layout:
            mark_health(cockpit["id"], service_type=layout.get("service_type"),
                        work_dir=layout.get("work_dir"))
        before = None
        if layout:
            try:
                before = engine.record_marker(
                    engine.read_last_upload(transport, layout))
            except Exception:  # noqa: BLE001
                before = None

        if action == "status":
            resp = transport.request({"action": "ping"})
            progress = engine.progress_of(resp)
            busy = resp.get("status") == "uploading"
            mark_health(cockpit["id"], ipc="ok", ipc_message=resp.get("status"))
            record = None
            if layout:
                try:
                    record = engine.read_last_upload(transport, layout)
                except Exception:  # noqa: BLE001
                    record = None
            set_job(job, state="done", finished_at=time.time(),
                    phase=progress.get("phase") or "idle",
                    percent=int(progress.get("percent") or 0),
                    bytes_sent=progress.get("bytes_sent") or 0,
                    bytes_total=progress.get("bytes_total") or 0,
                    kind=progress.get("kind") or "",
                    object_key=progress.get("object_key") or "",
                    reached_phase=progress.get("phase") or "idle",
                    last_upload=record,
                    message=("正在上传：" + engine.describe(progress)) if busy
                            else "空闲：" + engine.describe(progress))
            return

        resp = transport.request({"action": "upload_today"})
        status = resp.get("status")
        mark_health(cockpit["id"], ipc="ok", ipc_message=str(status))
        if status == "error":
            set_job(job, state="failed", verdict="failed", finished_at=time.time(),
                    message="服务端拒绝：%s" % resp.get("message"))
            return
        if status == "busy":
            set_job(job, state="running",
                    message="驾舱已经在传了（可能是定时任务），改为跟随当前任务")
        else:
            set_job(job, state="running", message="已触发：正在上报今天的日志")

        def on_update(phase, progress, elapsed):
            set_job(
                job,
                phase=phase or "idle",
                percent=int(progress.get("percent") or 0),
                bytes_sent=progress.get("bytes_sent") or 0,
                bytes_total=progress.get("bytes_total") or 0,
                kind=progress.get("kind") or "",
                object_key=progress.get("object_key") or "",
                elapsed=round(elapsed, 1),
                message=engine.describe(progress),
            )

        best, latest, timed_out = engine.follow(
            transport, on_update, poll_interval=POLL_INTERVAL,
            overall_timeout=JOB_TIMEOUT)
        result, why = engine.verdict(best, latest)
        record = None
        if layout:
            try:
                record = engine.read_last_upload(transport, layout)
                marker = engine.record_marker(record)
                if marker and marker != before:
                    result = "success"
                    why = ("驾舱 state.json 出现新的上传记录（%s，%.1f MiB）"
                           % (record.get("uploaded_at"),
                              float(record.get("size_bytes") or 0) / 1048576))
                elif result == "success":
                    result = "unknown"
                    why = "观测到收尾，但 state.json 没有新记录，请人工核对 work_dir"
            except Exception:  # noqa: BLE001
                record = None
        set_job(job, finished_at=time.time(), reached_phase=best, verdict=result,
                last_upload=record,
                state="failed" if result == "failed" else "done",
                message=("等待超时，任务可能还在跑；" if timed_out else "") + why)
    except engine.IpcError as exc:
        mark_health(cockpit["id"], ssh="ok", ipc="fail", ipc_message=str(exc))
        set_job(job, state="failed", verdict="unreachable",
                finished_at=time.time(), message=str(exc))
    except engine.EngineError as exc:
        mark_health(cockpit["id"], ssh="fail", ssh_error=str(exc))
        set_job(job, state="failed", verdict="unreachable",
                finished_at=time.time(), message=str(exc))
    except Exception as exc:  # noqa: BLE001
        set_job(job, state="failed", verdict="unreachable",
                finished_at=time.time(), message="内部错误：%r" % (exc,))
    finally:
        if transport is not None:
            transport.close()
        if use_slot:
            UPLOAD_SLOTS.release()
        audit(event="job", user=user, cockpit_id=cockpit["id"], action=action,
              state=job.get("state"), verdict=job.get("verdict"),
              percent=job.get("percent"),
              message=(job.get("message") or "")[:200])


def snapshot(batch_id):
    with LOCK:
        batch = BATCHES.get(batch_id)
        if batch is None:
            return None
        jobs = [dict(j) for j in batch["jobs"].values()]
    finished = [j for j in jobs if j["state"] in ("done", "failed")]
    return {
        "batch_id": batch_id,
        "action": batch["action"],
        "created_at": batch["created_at"],
        "all_done": len(finished) == len(jobs) and jobs != [],
        "counts": {
            "total": len(jobs),
            "done": len([j for j in jobs if j["state"] == "done"]),
            "failed": len([j for j in jobs if j["state"] == "failed"]),
            "running": len([j for j in jobs if j["state"] in ("running", "connecting")]),
        },
        "jobs": sorted(jobs, key=lambda j: (j["site"], j["cockpit_id"])),
    }


@app.get("/healthz")
def healthz():
    return {"ok": True, "cockpits": len(COCKPITS),
            "upload_concurrency": UPLOAD_CONCURRENCY}


@app.get("/api/cockpits")
def api_cockpits():
    sites = [{"id": s["id"], "name": s.get("name", s["id"]),
              "region": s.get("region", "")} for s in CONFIG.get("sites", [])]
    return JSONResponse({
        "sites": sites,
        "cockpits": [public_cockpit(c) for c in COCKPITS.values()],
        "upload_concurrency": UPLOAD_CONCURRENCY,
        "default_site": CONFIG.get("default_site", ""),
    })


@app.get("/api/health")
def api_health():
    with HEALTH_LOCK:
        return JSONResponse({
            "checked_at": time.time(),
            "interval": HEALTH_INTERVAL,
            "sites": dict(SITE_HEALTH),
            "cockpits": dict(COCKPIT_HEALTH),
        })


@app.get("/api/me")
def api_me(request: Request):
    return {"user": getattr(request.state, "user", "") or "anonymous",
            "users": len(APP_USERS)}


@app.get("/api/audit")
def api_audit(limit: int = 80):
    items = []
    if os.path.isfile(AUDIT_PATH):
        try:
            with open(AUDIT_PATH, "r", encoding="utf-8") as handle:
                lines = handle.readlines()[-max(1, min(limit, 500)):]
            for line in lines:
                try:
                    items.append(json.loads(line))
                except ValueError:
                    continue
        except OSError:
            pass
    return JSONResponse({"items": list(reversed(items))})


@app.post("/api/batches")
def api_create_batch(body: dict, request: Request):
    """body: {"cockpit_ids": [...], "action": "upload"|"status"}"""
    action = (body.get("action") or "upload").lower()
    if action not in ("upload", "status"):
        raise HTTPException(400, "action 只能是 upload 或 status")
    ids = body.get("cockpit_ids") or []
    if not ids:
        raise HTTPException(400, "没选驾舱")
    unknown = [i for i in ids if i not in COCKPITS]
    if unknown:
        raise HTTPException(400, "驾舱清单里没有：%s" % ", ".join(unknown))

    batch_id = uuid.uuid4().hex[:12]
    user = getattr(request.state, "user", "") or "anonymous"
    audit(event="batch", user=user, action=action, cockpits=ids,
          ip=(request.client.host if request.client else ""))
    jobs = {}
    for cockpit_id in ids:
        cockpit = dict(COCKPITS[cockpit_id])
        job = make_job(cockpit, action)
        jobs[cockpit_id] = job
        threading.Thread(target=run_job, daemon=True,
                         args=(job, cockpit, action, action == "upload",
                               user)).start()
    with LOCK:
        BATCHES[batch_id] = {"batch_id": batch_id, "action": action,
                             "created_at": time.time(), "jobs": jobs}
    return {"batch_id": batch_id, "action": action, "count": len(jobs)}


@app.get("/api/batches/{batch_id}")
def api_batch(batch_id: str):
    snap = snapshot(batch_id)
    if snap is None:
        raise HTTPException(404, "没有这个任务批次")
    return JSONResponse(snap)


@app.get("/api/latest")
def api_latest():
    """最近一个批次：页面刷新后能把还没跑完的任务接回来。"""
    with LOCK:
        if not BATCHES:
            return JSONResponse({"batch": None})
        batch_id, batch = max(BATCHES.items(),
                              key=lambda item: item[1]["created_at"])
    if time.time() - batch["created_at"] > 3600:
        return JSONResponse({"batch": None})
    return JSONResponse({"batch": batch_id, "snapshot": snapshot(batch_id)})


@app.get("/api/batches/{batch_id}/events")
async def api_events(batch_id: str):
    if snapshot(batch_id) is None:
        raise HTTPException(404, "没有这个任务批次")

    async def event_stream():
        last_payload = None
        last_ping = time.monotonic()
        while True:
            snap = snapshot(batch_id)
            if snap is None:
                return
            payload = json.dumps(snap, ensure_ascii=False)
            if payload != last_payload:
                yield "data: %s\n\n" % payload
                last_payload = payload
                last_ping = time.monotonic()
                if snap["all_done"]:
                    return
            elif time.monotonic() - last_ping > 10:
                yield ": keep-alive\n\n"
                last_ping = time.monotonic()
            await asyncio.sleep(0.3)

    return StreamingResponse(event_stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


@app.get("/")
def index():
    return FileResponse(os.path.join(HERE, "static", "index.html"))


if __name__ == "__main__":
    uvicorn.run(app, host=os.environ.get("HOST", "0.0.0.0"),
                port=int(os.environ.get("PORT", "8080")), log_level="info")
