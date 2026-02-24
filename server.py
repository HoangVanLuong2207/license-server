"""
License Key Server — FastAPI + Turso (libSQL)
Quản lý license key cho tool Garena Account Manager.

Endpoints:
  POST /api/verify        — Verify key + bind HWID
  POST /api/admin/keys    — Tạo key mới
  GET  /api/admin/keys    — Danh sách key
  DELETE /api/admin/keys/{key} — Xóa/revoke key
  GET  /                  — Admin panel HTML
"""

import hashlib
import os
import secrets
import time
from datetime import datetime, timedelta

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import libsql_client

# ============================================================
# CẤU HÌNH
# ============================================================
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")  # Đổi khi deploy!
TURSO_URL = os.environ.get("TURSO_URL")         # libSQL URL (VD: libsql://db-name.turso.io)
TURSO_AUTH_TOKEN = os.environ.get("TURSO_AUTH_TOKEN") # Auth Token từ Turso

if not TURSO_URL:
    # Nếu không có Turso URL, dùng SQLite local làm fallback
    TURSO_URL = "file:license.db"

app = FastAPI(title="License Key Server", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Khởi tạo client Turso
client = libsql_client.create_client(url=TURSO_URL, auth_token=TURSO_AUTH_TOKEN)

# ============================================================
# DATABASE
# ============================================================
async def init_db():
    """Tạo bảng nếu chưa tồn tại."""
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

# ============================================================
# MODELS
# ============================================================
class VerifyRequest(BaseModel):
    key: str
    hwid: str

class CreateKeyRequest(BaseModel):
    admin_password: str
    days: Optional[int] = None  # None = vĩnh viễn
    max_devices: int = 1
    note: str = ""

# ============================================================
# ADMIN AUTH
# ============================================================
def check_admin(password: str):
    if password != ADMIN_PASSWORD:
        raise HTTPException(status_code=403, detail="Sai mật khẩu admin")

# ============================================================
# API ENDPOINTS
# ============================================================

@app.on_event("startup")
async def startup():
    await init_db()

@app.on_event("shutdown")
async def shutdown():
    await client.close()

@app.post("/api/verify")
async def verify_key(req: VerifyRequest):
    """Xác thực license key + bind HWID."""
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
        # Lần đầu → bind HWID
        await client.execute(
            "UPDATE license_keys SET hwid = ?, last_verified = ? WHERE key = ?",
            (req.hwid, datetime.now().isoformat(), req.key)
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
    }

@app.post("/api/admin/keys")
async def create_key(req: CreateKeyRequest):
    """Tạo key mới."""
    check_admin(req.admin_password)

    new_key = secrets.token_hex(16).upper()
    new_key = "-".join([new_key[i:i+4] for i in range(0, 16, 4)])

    now = datetime.now().isoformat()
    expires = None
    if req.days and req.days > 0:
        expires = (datetime.now() + timedelta(days=req.days)).isoformat()

    await client.execute(
        """INSERT INTO license_keys (key, created_at, expires_at, max_devices, note)
           VALUES (?, ?, ?, ?, ?)""",
        (new_key, now, expires, req.max_devices, req.note)
    )

    return {
        "key": new_key,
        "expires_at": expires,
        "max_devices": req.max_devices,
        "note": req.note,
    }

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
          <select id="keyDays">
            <option value="0">Vĩnh viễn</option>
            <option value="7">7 ngày</option>
            <option value="30" selected>30 ngày</option>
            <option value="90">90 ngày</option>
            <option value="180">180 ngày</option>
            <option value="365">1 năm</option>
          </select>
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
        ${k.is_active
          ? `<button class="btn btn-danger btn-sm" onclick="revokeKey('${k.key}')">Khóa</button>`
          : `<button class="btn btn-success btn-sm" onclick="activateKey('${k.key}')">Mở</button>`
        }
        <button class="btn btn-warning btn-sm" onclick="resetHwid('${k.key}')">Reset HWID</button>
      </td>
    `;
    tbody.appendChild(row);
  });
}

async function createKey() {
  const days = parseInt(document.getElementById('keyDays').value) || null;
  const note = document.getElementById('keyNote').value;

  const res = await fetch(`${API}/api/admin/keys`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ admin_password: ADMIN_PASS, days, note })
  });
  const data = await res.json();
  toast(`Key tạo thành công: ${data.key}`);
  document.getElementById('keyNote').value = '';
  loadKeys();
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
