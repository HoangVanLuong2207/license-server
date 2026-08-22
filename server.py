"""
License Key Server — FastAPI + Turso (libSQL)
Quản lý license key cho tool Garena Account Manager.

Endpoints:
  POST /api/verify        — Verify key + bind HWID
  POST /api/admin/keys    — Tạo key mới
  GET  /api/admin/keys    — Danh sách key
  DELETE /api/admin/keys/{key} — Xóa/revoke key
  GET  /ping              — Health check (keep-alive)
  GET  /                  — Admin panel HTML
"""

import hashlib
import base64
import json
import os
import re
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from typing import Optional
import libsql_client
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# ============================================================
# CẤU HÌNH
# ============================================================
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
TURSO_URL = os.environ.get("TURSO_URL")         # libSQL URL (VD: libsql://db-name.turso.io)
TURSO_AUTH_TOKEN = os.environ.get("TURSO_AUTH_TOKEN") # Auth Token từ Turso
SIGNING_PRIVATE_KEY_B64 = os.environ.get("LICENSE_SIGNING_PRIVATE_KEY", "")

if not SIGNING_PRIVATE_KEY_B64:
    raise RuntimeError("Thiếu biến môi trường LICENSE_SIGNING_PRIVATE_KEY")
try:
    SIGNING_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(SIGNING_PRIVATE_KEY_B64, validate=True)
    )
except Exception as error:
    raise RuntimeError("LICENSE_SIGNING_PRIVATE_KEY không phải Ed25519 private key base64 hợp lệ") from error

SIGNING_PUBLIC_KEY = SIGNING_PRIVATE_KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
SIGNING_KEY_FINGERPRINT = hashlib.sha256(SIGNING_PUBLIC_KEY).hexdigest()[:16].upper()

if not TURSO_URL:
    # Nếu không có Turso URL, dùng SQLite local làm fallback
    TURSO_URL = "file:license.db"
else:
    # Render đôi khi lỗi WebSocket (505), nên ép dùng HTTPS nếu là link libsql://
    if TURSO_URL.startswith("libsql://"):
        TURSO_URL = TURSO_URL.replace("libsql://", "https://", 1)

app = FastAPI(title="License Key Server", version="1.0")

# Client Turso phải được tạo sau khi Uvicorn đã khởi động event loop.
client = None

# ============================================================
# DATABASE
# ============================================================
async def init_db():
    """Tạo bảng nếu chưa tồn tại."""
    if client is None:
        raise RuntimeError("Database client chưa được khởi tạo")
    await client.execute("""
        CREATE TABLE IF NOT EXISTS license_keys (
            key TEXT PRIMARY KEY,
            hwid TEXT DEFAULT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT DEFAULT NULL,
            max_devices INTEGER DEFAULT 1,
            is_active INTEGER DEFAULT 1,
            note TEXT DEFAULT '',
            last_verified TEXT DEFAULT NULL
        )
    """)
    await client.execute("""
        CREATE TABLE IF NOT EXISTS flow_scripts (
            name TEXT PRIMARY KEY,
            content TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            is_active INTEGER DEFAULT 1
        )
    """)

# ============================================================
# MODELS
# ============================================================
class VerifyRequest(BaseModel):
    key: str = Field(min_length=8, max_length=128)
    hwid: str = Field(min_length=16, max_length=128)
    nonce: str = Field(min_length=16, max_length=128)

class CreateKeyRequest(BaseModel):
    admin_password: str
    days: Optional[int] = None  # Số ngày (tùy chọn)
    custom_date: Optional[str] = None # YYYY-MM-DD (tùy chọn)
    max_devices: int = 1
    note: str = ""

class ExtendKeyRequest(BaseModel):
    admin_password: str
    days: int

class ScriptAccessRequest(BaseModel):
    key: str = Field(min_length=8, max_length=128)
    hwid: str = Field(min_length=16, max_length=128)
    nonce: str = Field(min_length=16, max_length=128)

class ScriptSyncItem(BaseModel):
    name: str = Field(min_length=6, max_length=128)
    content: list[dict]

class ScriptSyncRequest(BaseModel):
    admin_password: str
    scripts: list[ScriptSyncItem]
    replace_all: bool = True

# ============================================================
# ADMIN AUTH
# ============================================================
def check_admin(password: str):
    if not ADMIN_PASSWORD:
        raise HTTPException(status_code=503, detail="Server chưa cấu hình ADMIN_PASSWORD")
    if not secrets.compare_digest(password, ADMIN_PASSWORD):
        raise HTTPException(status_code=403, detail="Sai mật khẩu admin")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _signed_payload(payload: dict) -> str:
    encoded = _b64url(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    signature = _b64url(SIGNING_PRIVATE_KEY.sign(encoded.encode("ascii")))
    return f"{encoded}.{signature}"


def _signed_token(key: str, hwid: str, nonce: str) -> str:
    now = int(time.time())
    payload = {
        "v": 1,
        "product": "ToolAOV",
        "key_hash": hashlib.sha256(key.encode("utf-8")).hexdigest(),
        "hwid": hwid,
        "nonce": nonce,
        "iat": now,
        "exp": now + 300,
    }
    return _signed_payload(payload)


def _canonical_json(value) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def _script_name(value: str) -> str:
    name = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}\.json", name) or ".." in name:
        raise HTTPException(status_code=400, detail="Tên script không hợp lệ")
    return name


async def _require_bound_license(key: str, hwid: str):
    """Fail closed unless the key is active, unexpired, and bound to this HWID."""
    rs = await client.execute(
        "SELECT hwid, expires_at, is_active FROM license_keys WHERE key = ?",
        (key,),
    )
    if not rs.rows:
        raise HTTPException(status_code=403, detail="Key không tồn tại")
    bound_hwid, expires_at, is_active = rs.rows[0]
    if not is_active:
        raise HTTPException(status_code=403, detail="Key đã bị khóa")
    if expires_at and datetime.now() > datetime.fromisoformat(expires_at):
        raise HTTPException(status_code=403, detail="Key đã hết hạn")
    if not bound_hwid or not secrets.compare_digest(str(bound_hwid), str(hwid)):
        raise HTTPException(status_code=403, detail="Key không thuộc thiết bị này")


def _script_attestation(kind: str, key: str, hwid: str, nonce: str, **claims) -> str:
    now = int(time.time())
    payload = {
        "v": 1,
        "product": "ToolAOV",
        "kind": kind,
        "key_hash": hashlib.sha256(key.encode("utf-8")).hexdigest(),
        "hwid": hwid,
        "nonce": nonce,
        "iat": now,
        "exp": now + 120,
        **claims,
    }
    return _signed_payload(payload)


_VERIFY_HITS = defaultdict(deque)
_SCRIPT_HITS = defaultdict(deque)


def check_verify_rate(request: Request, key: str):
    """Limit each IP/key pair to 40 verification attempts per minute."""
    client_ip = request.headers.get("x-forwarded-for", "").split(",", 1)[0].strip()
    if not client_ip:
        client_ip = request.client.host if request.client else "unknown"
    bucket_id = hashlib.sha256(f"{client_ip}|{key}".encode("utf-8")).hexdigest()
    now = time.monotonic()
    hits = _VERIFY_HITS[bucket_id]
    while hits and now - hits[0] > 60:
        hits.popleft()
    if len(hits) >= 40:
        raise HTTPException(status_code=429, detail="Quá nhiều yêu cầu xác thực, vui lòng thử lại sau")
    hits.append(now)


def check_script_rate(request: Request, key: str):
    """Allow normal chains while bounding automated key/resource scraping."""
    client_ip = request.headers.get("x-forwarded-for", "").split(",", 1)[0].strip()
    if not client_ip:
        client_ip = request.client.host if request.client else "unknown"
    bucket_id = hashlib.sha256(f"script|{client_ip}|{key}".encode("utf-8")).hexdigest()
    now = time.monotonic()
    hits = _SCRIPT_HITS[bucket_id]
    while hits and now - hits[0] > 60:
        hits.popleft()
    if len(hits) >= 300:
        raise HTTPException(status_code=429, detail="Quá nhiều yêu cầu script, vui lòng thử lại sau")
    hits.append(now)

# ============================================================
# API ENDPOINTS
# ============================================================

@app.on_event("startup")
async def startup():
    global client
    print(f"[*] Connecting Database: {TURSO_URL.split('://')[0]}://***")
    client = libsql_client.create_client(url=TURSO_URL, auth_token=TURSO_AUTH_TOKEN)
    await init_db()

@app.on_event("shutdown")
async def shutdown():
    global client
    if client is not None:
        await client.close()
        client = None

@app.get("/ping")
async def ping():
    """Health check — dùng để ping giữ server không bị ngủ."""
    rs = await client.execute("SELECT COUNT(*) FROM flow_scripts WHERE is_active = 1")
    script_count = int(rs.rows[0][0]) if rs.rows else 0
    return {
        "status": "ok",
        "signing_key": SIGNING_KEY_FINGERPRINT,
        "script_api": 1,
        "scripts_ready": script_count > 0,
        "script_count": script_count,
    }

@app.post("/api/verify")
async def verify_key(req: VerifyRequest, request: Request):
    """Xác thực license key + bind HWID."""
    check_verify_rate(request, req.key)
    rs = await client.execute("SELECT * FROM license_keys WHERE key = ?", (req.key,))
    rows = rs.rows
    
    if not rows:
        return JSONResponse(
            status_code=200,
            content={"valid": False, "message": "Key không tồn tại"}
        )

    row = rows[0]
    r_dict = {col: row[i] for i, col in enumerate(rs.columns)}

    if not r_dict["is_active"]:
        return JSONResponse(
            status_code=200,
            content={"valid": False, "message": "Key đã bị khóa"}
        )

    # Check hết hạn
    if r_dict["expires_at"]:
        expires = datetime.fromisoformat(r_dict["expires_at"])
        if datetime.now() > expires:
            return JSONResponse(
                status_code=200,
                content={"valid": False, "message": f"Key đã hết hạn ({r_dict['expires_at']})"}
            )

    # HWID binding
    if r_dict["hwid"] is None or r_dict["hwid"] == "":
        # Bind có điều kiện để hai máy kích hoạt đồng thời không thể cùng thắng.
        await client.execute(
            """UPDATE license_keys SET hwid = ?, last_verified = ?
               WHERE key = ? AND (hwid IS NULL OR hwid = '')""",
            (req.hwid, datetime.now().isoformat(), req.key)
        )
        bound = await client.execute("SELECT hwid FROM license_keys WHERE key = ?", (req.key,))
        if not bound.rows or bound.rows[0][0] != req.hwid:
            return JSONResponse(
                status_code=200,
                content={"valid": False, "message": "Key đã được dùng trên thiết bị khác"}
            )
    elif r_dict["hwid"] != req.hwid:
        return JSONResponse(
            status_code=200,
            content={"valid": False, "message": "Key đã được dùng trên thiết bị khác"}
        )
    else:
        # Update last_verified
        await client.execute(
            "UPDATE license_keys SET last_verified = ? WHERE key = ?",
            (datetime.now().isoformat(), req.key)
        )

    return {
        "valid": True,
        "message": "OK",
        "expires": r_dict["expires_at"],
        "token": _signed_token(req.key, req.hwid, req.nonce),
    }


@app.post("/api/scripts/bundle")
async def download_script_bundle(req: ScriptAccessRequest, request: Request):
    """Return scripts only to an active key already bound to this HWID."""
    check_script_rate(request, req.key)
    await _require_bound_license(req.key, req.hwid)
    rs = await client.execute(
        "SELECT name, content FROM flow_scripts WHERE is_active = 1 ORDER BY name"
    )
    scripts = {}
    for row in rs.rows:
        name = _script_name(str(row[0]))
        try:
            content = json.loads(str(row[1]))
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise HTTPException(status_code=500, detail=f"Script hỏng trên server: {name}") from error
        if not isinstance(content, list):
            raise HTTPException(status_code=500, detail=f"Script không phải danh sách: {name}")
        scripts[name] = content
    if not scripts:
        raise HTTPException(status_code=503, detail="Server chưa có script hoạt động")
    bundle_hash = hashlib.sha256(_canonical_json(scripts).encode("utf-8")).hexdigest()
    return {
        "scripts": scripts,
        "attestation": _script_attestation(
            "script_bundle",
            req.key,
            req.hwid,
            req.nonce,
            bundle_hash=bundle_hash,
            script_count=len(scripts),
        ),
    }


@app.post("/api/scripts/{name}/authorize")
async def authorize_script_run(name: str, req: ScriptAccessRequest, request: Request):
    """Issue a short-lived, request-bound ticket immediately before a script runs."""
    check_script_rate(request, req.key)
    await _require_bound_license(req.key, req.hwid)
    name = _script_name(name)
    rs = await client.execute(
        "SELECT sha256 FROM flow_scripts WHERE name = ? AND is_active = 1",
        (name,),
    )
    if not rs.rows:
        raise HTTPException(status_code=404, detail="Script không tồn tại hoặc đã bị khóa")
    script_hash = str(rs.rows[0][0])
    return {
        "authorized": True,
        "ticket": _script_attestation(
            "script_run",
            req.key,
            req.hwid,
            req.nonce,
            script_name=name,
            script_hash=script_hash,
        ),
    }


@app.post("/api/admin/scripts/sync")
async def sync_scripts(req: ScriptSyncRequest):
    """Upsert the trusted local script set into Turso without publishing it to Git."""
    check_admin(req.admin_password)
    if not req.scripts:
        raise HTTPException(status_code=400, detail="Danh sách script trống")
    normalized = []
    seen = set()
    for item in req.scripts:
        name = _script_name(item.name)
        if name in seen:
            raise HTTPException(status_code=400, detail=f"Trùng tên script: {name}")
        seen.add(name)
        content = json.loads(_canonical_json(item.content))
        canonical = _canonical_json(content)
        normalized.append(
            (name, canonical, hashlib.sha256(canonical.encode("utf-8")).hexdigest())
        )
    if req.replace_all:
        await client.execute("UPDATE flow_scripts SET is_active = 0")
    now = datetime.now().isoformat()
    for name, content, digest in normalized:
        await client.execute(
            """INSERT INTO flow_scripts (name, content, sha256, updated_at, is_active)
               VALUES (?, ?, ?, ?, 1)
               ON CONFLICT(name) DO UPDATE SET
                   content = excluded.content,
                   sha256 = excluded.sha256,
                   updated_at = excluded.updated_at,
                   is_active = 1""",
            (name, content, digest, now),
        )
    return {"synced": len(normalized), "replace_all": req.replace_all}


@app.get("/api/admin/scripts")
async def list_scripts_admin(admin_password: str):
    check_admin(admin_password)
    rs = await client.execute(
        "SELECT name, sha256, updated_at, is_active FROM flow_scripts ORDER BY name"
    )
    return [{col: row[i] for i, col in enumerate(rs.columns)} for row in rs.rows]

@app.post("/api/admin/keys")
async def create_key(req: CreateKeyRequest):
    """Tạo key mới."""
    check_admin(req.admin_password)

    new_key = secrets.token_hex(16).upper()
    new_key = "-".join([new_key[i:i+4] for i in range(0, len(new_key), 4)])

    now = datetime.now()
    expires = None

    if req.custom_date:
        try:
            expires = datetime.fromisoformat(req.custom_date).replace(hour=23, minute=59, second=59).isoformat()
        except ValueError:
            raise HTTPException(status_code=400, detail="Định dạng ngày không hợp lệ (YYYY-MM-DD)")
    elif req.days and req.days > 0:
        expires = (now + timedelta(days=req.days)).isoformat()

    await client.execute(
        """INSERT INTO license_keys (key, created_at, expires_at, max_devices, note)
           VALUES (?, ?, ?, ?, ?)""",
        (new_key, now.isoformat(), expires, req.max_devices, req.note)
    )

    return {
        "key": new_key,
        "expires_at": expires,
        "max_devices": req.max_devices,
        "note": req.note,
    }

@app.put("/api/admin/keys/{key}/extend")
async def extend_key(key: str, req: ExtendKeyRequest):
    """Gia hạn thêm ngày cho key."""
    check_admin(req.admin_password)

    rs = await client.execute("SELECT expires_at FROM license_keys WHERE key = ?", (key,))
    if not rs.rows:
        raise HTTPException(status_code=404, detail="Key không tồn tại")
    
    current_expires = rs.rows[0][0]
    
    # Nếu đang vĩnh viễn (expires_at = NULL), không cần gia hạn trừ khi set lại
    if current_expires is None:
        return {"message": "Key đang là vĩnh viễn, không cần gia hạn", "expires_at": None}

    base_date = datetime.fromisoformat(current_expires)
    # Nếu đã hết hạn thì tính từ thời điểm hiện tại, nếu chưa thì cộng dồn
    if base_date < datetime.now():
        base_date = datetime.now()
    
    new_expires = (base_date + timedelta(days=req.days)).isoformat()
    
    await client.execute("UPDATE license_keys SET expires_at = ? WHERE key = ?", (new_expires, key))
    
    return {"message": f"Đã gia hạn thêm {req.days} ngày", "new_expires": new_expires}

@app.get("/api/admin/keys")
async def list_keys(admin_password: str):
    """Danh sách tất cả key."""
    check_admin(admin_password)

    rs = await client.execute("SELECT * FROM license_keys ORDER BY created_at DESC")
    return [{col: row[i] for i, col in enumerate(rs.columns)} for row in rs.rows]

@app.delete("/api/admin/keys/{key}")
async def revoke_key(key: str, admin_password: str):
    """Khóa key."""
    check_admin(admin_password)

    rs = await client.execute("SELECT key FROM license_keys WHERE key = ?", (key,))
    if not rs.rows:
        raise HTTPException(status_code=404, detail="Key không tồn tại")

    await client.execute("UPDATE license_keys SET is_active = 0 WHERE key = ?", (key,))
    return {"message": f"Đã khóa key {key}"}

@app.put("/api/admin/keys/{key}/reset-hwid")
async def reset_hwid(key: str, admin_password: str):
    """Reset HWID."""
    check_admin(admin_password)

    rs = await client.execute("SELECT key FROM license_keys WHERE key = ?", (key,))
    if not rs.rows:
        raise HTTPException(status_code=404, detail="Key không tồn tại")

    await client.execute("UPDATE license_keys SET hwid = NULL WHERE key = ?", (key,))
    return {"message": f"Đã reset HWID cho key {key}"}

@app.put("/api/admin/keys/{key}/activate")
async def activate_key(key: str, admin_password: str):
    """Kích hoạt lại key."""
    check_admin(admin_password)

    await client.execute("UPDATE license_keys SET is_active = 1 WHERE key = ?", (key,))
    return {"message": f"Đã kích hoạt lại key {key}"}

# ============================================================
# ADMIN PANEL HTML
# ============================================================
@app.get("/", response_class=HTMLResponse)
async def admin_panel():
    return ADMIN_HTML

ADMIN_HTML = """<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>License Key Admin</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: #0f0f23;
    color: #e0e0e0;
    min-height: 100vh;
  }
  .container { max-width: 900px; margin: 0 auto; padding: 20px; }
  h1 {
    text-align: center;
    padding: 30px 0 10px;
    color: #00d4ff;
    font-size: 1.8em;
    letter-spacing: 2px;
  }
  .subtitle {
    text-align: center;
    color: #666;
    margin-bottom: 30px;
    font-size: 0.9em;
  }

  /* Login */
  .login-box {
    background: #1a1a2e;
    border: 1px solid #333;
    border-radius: 12px;
    padding: 30px;
    max-width: 400px;
    margin: 60px auto;
  }
  .login-box h2 { color: #00d4ff; margin-bottom: 20px; text-align: center; }
  .login-box input {
    width: 100%;
    padding: 12px;
    border: 1px solid #333;
    border-radius: 8px;
    background: #16213e;
    color: #fff;
    font-size: 1em;
    margin-bottom: 15px;
  }
  .login-box button {
    width: 100%;
    padding: 12px;
    border: none;
    border-radius: 8px;
    background: #00d4ff;
    color: #000;
    font-weight: bold;
    font-size: 1em;
    cursor: pointer;
    transition: all 0.2s;
  }
  .login-box button:hover { background: #00b8d4; transform: translateY(-1px); }

  /* Cards */
  .card {
    background: #1a1a2e;
    border: 1px solid #333;
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 20px;
  }
  .card h2 { color: #00d4ff; margin-bottom: 15px; font-size: 1.2em; }

  /* Create form */
  .create-form { display: flex; gap: 10px; flex-wrap: wrap; align-items: flex-end; }
  .create-form .field { display: flex; flex-direction: column; }
  .create-form label { font-size: 0.8em; color: #888; margin-bottom: 4px; }
  .create-form input, .create-form select {
    padding: 8px 12px;
    border: 1px solid #333;
    border-radius: 6px;
    background: #16213e;
    color: #fff;
    font-size: 0.9em;
  }
  .btn {
    padding: 8px 16px;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    font-size: 0.85em;
    font-weight: 600;
    transition: all 0.2s;
  }
  .btn-primary { background: #00d4ff; color: #000; }
  .btn-primary:hover { background: #00b8d4; }
  .btn-danger { background: #dc3545; color: #fff; }
  .btn-danger:hover { background: #c82333; }
  .btn-warning { background: #ffc107; color: #000; }
  .btn-warning:hover { background: #e0a800; }
  .btn-success { background: #28a745; color: #fff; }
  .btn-success:hover { background: #218838; }
  .btn-sm { padding: 4px 10px; font-size: 0.8em; }

  /* Table */
  table { width: 100%; border-collapse: collapse; font-size: 0.85em; }
  th { text-align: left; color: #00d4ff; padding: 10px 8px; border-bottom: 2px solid #333; }
  td { padding: 8px; border-bottom: 1px solid #222; vertical-align: middle; }
  tr:hover { background: #16213e; }

  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.8em;
    font-weight: 600;
  }
  .badge-active { background: #28a74533; color: #28a745; }
  .badge-inactive { background: #dc354533; color: #dc3545; }
  .badge-expired { background: #ffc10733; color: #ffc107; }

  .key-text {
    font-family: 'Consolas', monospace;
    background: #16213e;
    padding: 2px 6px;
    border-radius: 4px;
    cursor: pointer;
    user-select: all;
  }

  .toast {
    position: fixed;
    top: 20px;
    right: 20px;
    padding: 12px 20px;
    border-radius: 8px;
    font-weight: 600;
    z-index: 999;
    animation: fadeIn 0.3s;
  }
  .toast-success { background: #28a745; color: #fff; }
  .toast-error { background: #dc3545; color: #fff; }
  @keyframes fadeIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; } }

  .actions { display: flex; gap: 4px; }

  .hidden { display: none; }
</style>
</head>
<body>

<!-- Login Screen -->
<div id="loginScreen">
  <div class="login-box">
    <h2>🔐 Admin Login</h2>
    <input type="password" id="adminPass" placeholder="Nhập mật khẩu admin..." onkeydown="if(event.key==='Enter')login()">
    <button onclick="login()">Đăng nhập</button>
  </div>
</div>

<!-- Admin Panel -->
<div id="adminPanel" class="hidden">
  <div class="container">
    <h1>🔑 License Key Admin</h1>
    <p class="subtitle">Quản lý license key cho Garena Account Manager</p>

    <!-- Create Key -->
    <div class="card">
      <h2>➕ Tạo Key Mới</h2>
      <div class="create-form">
        <div class="field">
          <label>Thời hạn</label>
          <select id="keyDays" onchange="toggleCustomDate()">
            <option value="0">Vĩnh viễn</option>
            <option value="7">7 ngày</option>
            <option value="30" selected>30 ngày</option>
            <option value="90">90 ngày</option>
            <option value="365">1 năm</option>
            <option value="custom">Chọn ngày cụ thể...</option>
          </select>
        </div>
        <div id="customDateContainer" class="field hidden">
          <label>Ngày hết hạn</label>
          <input type="date" id="keyCustomDate">
        </div>
        <div class="field">
          <label>Ghi chú</label>
          <input type="text" id="keyNote" placeholder="VD: Khách hàng A" style="width:200px">
        </div>
        <button class="btn btn-primary" onclick="createKey()">Tạo Key</button>
      </div>
    </div>

    <!-- Key List -->
    <div class="card">
      <h2>📋 Danh Sách Key (<span id="keyCount">0</span>)</h2>
      <table>
        <thead>
          <tr>
            <th>Key</th>
            <th>Trạng thái</th>
            <th>Hết hạn</th>
            <th>HWID</th>
            <th>Ghi chú</th>
            <th>Hành động</th>
          </tr>
        </thead>
        <tbody id="keyTable"></tbody>
      </table>
    </div>
  </div>
</div>

<script>
let ADMIN_PASS = '';
const API = window.location.origin;

function toast(msg, type='success') {
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3000);
}

async function login() {
  ADMIN_PASS = document.getElementById('adminPass').value;
  try {
    const res = await fetch(`${API}/api/admin/keys?admin_password=${encodeURIComponent(ADMIN_PASS)}`);
    if (res.status === 403) { toast('Sai mật khẩu!', 'error'); return; }
    document.getElementById('loginScreen').classList.add('hidden');
    document.getElementById('adminPanel').classList.remove('hidden');
    loadKeys();
  } catch(e) {
    toast('Lỗi kết nối server', 'error');
  }
}

async function loadKeys() {
  const res = await fetch(`${API}/api/admin/keys?admin_password=${encodeURIComponent(ADMIN_PASS)}`);
  const keys = await res.json();
  document.getElementById('keyCount').textContent = keys.length;

  const tbody = document.getElementById('keyTable');
  tbody.innerHTML = '';

  keys.forEach(k => {
    const isExpired = k.expires_at && new Date(k.expires_at) < new Date();
    let status = '';
    if (!k.is_active) status = '<span class="badge badge-inactive">Đã khóa</span>';
    else if (isExpired) status = '<span class="badge badge-expired">Hết hạn</span>';
    else status = '<span class="badge badge-active">Hoạt động</span>';

    const expires = k.expires_at ? new Date(k.expires_at).toLocaleDateString('vi-VN') : 'Vĩnh viễn';
    const hwid = k.hwid ? k.hwid.substring(0, 8) + '...' : '—';

    const row = document.createElement('tr');
    row.innerHTML = `
      <td><span class="key-text" onclick="copyKey(this)" title="Click để copy">${k.key}</span></td>
      <td>${status}</td>
      <td>${expires}</td>
      <td>${hwid}</td>
      <td>${k.note || '—'}</td>
      <td class="actions">
        <div style="display:flex; flex-direction:column; gap:4px">
          <div class="actions">
            ${k.is_active
              ? `<button class="btn btn-danger btn-sm" onclick="revokeKey('${k.key}')">Khóa</button>`
              : `<button class="btn btn-success btn-sm" onclick="activateKey('${k.key}')">Mở</button>`
            }
            <button class="btn btn-warning btn-sm" onclick="resetHwid('${k.key}')">Reset HWID</button>
          </div>
          <div class="actions">
            <button class="btn btn-primary btn-sm" onclick="extendKeyPrompt('${k.key}')">➕ Gia hạn</button>
          </div>
        </div>
      </td>
    `;
    tbody.appendChild(row);
  });
}

function toggleCustomDate() {
  const val = document.getElementById('keyDays').value;
  const container = document.getElementById('customDateContainer');
  if (val === 'custom') container.classList.remove('hidden');
  else container.classList.add('hidden');
}

async function createKey() {
  const type = document.getElementById('keyDays').value;
  let days = null;
  let custom_date = null;

  if (type === 'custom') {
    custom_date = document.getElementById('keyCustomDate').value;
    if (!custom_date) { toast('Vui lòng chọn ngày!', 'error'); return; }
  } else {
    days = parseInt(type) || null;
  }
  
  const note = document.getElementById('keyNote').value;

  const res = await fetch(`${API}/api/admin/keys`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ admin_password: ADMIN_PASS, days, custom_date, note })
  });
  if (!res.ok) {
    const err = await res.json();
    toast(err.detail || 'Lỗi khi tạo key', 'error');
    return;
  }
  const data = await res.json();
  toast(`Key tạo thành công: ${data.key}`);
  document.getElementById('keyNote').value = '';
  loadKeys();
}

async function extendKeyPrompt(key) {
  const days = prompt(`Gia hạn thêm bao nhiêu ngày cho key ${key}?`, "30");
  if (days === null || days === "") return;
  const daysInt = parseInt(days);
  if (isNaN(daysInt)) { toast('Số ngày không hợp lệ', 'error'); return; }

  const res = await fetch(`${API}/api/admin/keys/${key}/extend`, {
    method: 'PUT',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ admin_password: ADMIN_PASS, days: daysInt })
  });
  
  if (res.ok) {
    toast(`Đã gia hạn thêm ${daysInt} ngày`);
    loadKeys();
  } else {
    const err = await res.json();
    toast(err.detail || 'Lỗi gia hạn', 'error');
  }
}

async function revokeKey(key) {
  if (!confirm(`Khóa key ${key}?`)) return;
  await fetch(`${API}/api/admin/keys/${key}?admin_password=${encodeURIComponent(ADMIN_PASS)}`, { method: 'DELETE' });
  toast('Đã khóa key');
  loadKeys();
}

async function activateKey(key) {
  await fetch(`${API}/api/admin/keys/${key}/activate?admin_password=${encodeURIComponent(ADMIN_PASS)}`, { method: 'PUT' });
  toast('Đã kích hoạt lại key');
  loadKeys();
}

async function resetHwid(key) {
  if (!confirm(`Reset HWID cho key ${key}?\\nKey sẽ có thể dùng trên thiết bị khác.`)) return;
  await fetch(`${API}/api/admin/keys/${key}/reset-hwid?admin_password=${encodeURIComponent(ADMIN_PASS)}`, { method: 'PUT' });
  toast('Đã reset HWID');
  loadKeys();
}

function copyKey(el) {
  navigator.clipboard.writeText(el.textContent);
  toast('Đã copy key!');
}
</script>
</body>
</html>
"""
