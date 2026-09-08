"""
License Key Server — FastAPI + PostgreSQL / SQLite
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
import sqlite3
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from typing import Optional
import asyncpg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# ============================================================
# CẤU HÌNH
# ============================================================
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
SQLITE_PATH = os.environ.get("SQLITE_PATH", "license.db")
SIGNING_PRIVATE_KEY_B64 = os.environ.get("LICENSE_SIGNING_PRIVATE_KEY", "")
# Shared secret used only by AOVshop to issue a purchased Checkpass license.
AOVSHOP_ISSUER_TOKEN = os.environ.get("AOVSHOP_ISSUER_TOKEN", "")

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

app = FastAPI(title="License Key Server", version="1.0")

# PostgreSQL is used when DATABASE_URL is configured; SQLite is a local fallback.
class QueryResult:
    def __init__(self, rows=(), columns=()):
        self.rows = rows
        self.columns = columns


class Database:
    def __init__(self, database_url: str, sqlite_path: str):
        self.database_url = database_url
        self.sqlite_path = sqlite_path
        self.pool = None
        self.sqlite = None

    async def connect(self):
        if self.database_url:
            if not self.database_url.startswith(("postgres://", "postgresql://")):
                raise RuntimeError("DATABASE_URL phải là PostgreSQL URL (postgresql://...)")
            self.pool = await asyncpg.create_pool(self.database_url, min_size=1, max_size=5)
        else:
            self.sqlite = sqlite3.connect(self.sqlite_path, check_same_thread=False)

    @staticmethod
    def _postgres_sql(sql: str) -> str:
        index = 0
        parts = []
        for char in sql:
            if char == "?":
                index += 1
                parts.append(f"${index}")
            else:
                parts.append(char)
        return "".join(parts)

    async def execute(self, sql: str, args=()):
        if self.pool:
            async with self.pool.acquire() as connection:
                rows = await connection.fetch(self._postgres_sql(sql), *args)
                columns = tuple(rows[0].keys()) if rows else ()
                return QueryResult([tuple(row.values()) for row in rows], columns)
        if self.sqlite is None:
            raise RuntimeError("Database client chưa được khởi tạo")
        cursor = self.sqlite.execute(sql, args)
        self.sqlite.commit()
        columns = tuple(item[0] for item in cursor.description) if cursor.description else ()
        return QueryResult(cursor.fetchall() if cursor.description else [], columns)

    async def close(self):
        if self.pool:
            await self.pool.close()
            self.pool = None
        if self.sqlite:
            self.sqlite.close()
            self.sqlite = None


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
            last_verified TEXT DEFAULT NULL,
            source TEXT DEFAULT '',
            external_order_id TEXT DEFAULT NULL
        )
    """)
    # Safe migration for databases created by an older server version.
    for statement in (
        "ALTER TABLE license_keys ADD COLUMN source TEXT DEFAULT ''",
        "ALTER TABLE license_keys ADD COLUMN external_order_id TEXT DEFAULT NULL",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_license_keys_source_order ON license_keys(source, external_order_id)",
    ):
        try:
            await client.execute(statement)
        except Exception:
            # Existing column / index is expected after the first startup.
            pass
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

class MasterVerifyRequest(BaseModel):
    key: str = Field(min_length=1, max_length=128)

class CreateKeyRequest(BaseModel):
    admin_password: str
    days: Optional[int] = None  # Số ngày (tùy chọn)
    hours: Optional[int] = None  # Số giờ (tùy chọn)
    custom_date: Optional[str] = None # YYYY-MM-DD (tùy chọn)
    max_devices: int = 1
    note: str = ""

class ExtendKeyRequest(BaseModel):
    admin_password: str
    days: Optional[int] = None
    hours: Optional[int] = None

class IssueShopKeyRequest(BaseModel):
    order_id: int = Field(gt=0)
    product_id: int = Field(gt=0)
    duration_hours: int = Field(gt=0, le=8760)
    customer_email: Optional[str] = Field(default=None, max_length=320)

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


def _new_license_key() -> str:
    raw = secrets.token_hex(16).upper()
    return "-".join(raw[i:i + 4] for i in range(0, len(raw), 4))


def _require_aovshop_issuer(request: Request) -> None:
    if not AOVSHOP_ISSUER_TOKEN:
        raise HTTPException(status_code=503, detail="Server chưa cấu hình AOVSHOP_ISSUER_TOKEN")
    supplied = request.headers.get("X-AOVShop-Issuer-Token", "")
    if not supplied or not secrets.compare_digest(supplied, AOVSHOP_ISSUER_TOKEN):
        raise HTTPException(status_code=403, detail="Không có quyền cấp key từ AOVshop")


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
    if not re.fullmatch(r"[A-Za-z0-9_. -]{1,128}\.json", name) or ".." in name:
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
    target = "PostgreSQL" if DATABASE_URL else f"SQLite ({SQLITE_PATH})"
    print(f"[*] Connecting Database: {target}")
    client = Database(DATABASE_URL, SQLITE_PATH)
    await client.connect()
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


@app.post("/api/master-verify")
@app.get("/api/master-verify")
@app.post("/api/verify-simple")
@app.get("/api/verify-simple")
@app.post("/api/check")
@app.get("/api/check")
async def master_verify_simple(request: Request):
    """Verify đơn giản cho master — chỉ cần key, không cần hwid/nonce. Dùng cho checkpass master."""
    # Lấy key từ JSON body hoặc query
    key = ""
    if request.method == "POST":
        try:
            body = await request.json()
            if isinstance(body, dict):
                key = str(body.get("key") or body.get("token") or "").strip()
        except Exception:
            pass
    if not key:
        # Thử query param
        key = request.query_params.get("key") or request.query_params.get("token") or ""
        key = key.strip()
    if not key:
        # Thử form
        try:
            form = await request.form()
            key = str(form.get("key") or form.get("token") or "").strip()
        except Exception:
            pass
    if not key:
        return JSONResponse(status_code=200, content={"valid": False, "message": "thiếu key"})
    # Kiểm tra đơn giản: tồn tại, active, chưa hết hạn (không check hwid)
    try:
        rs = await client.execute("SELECT is_active, expires_at FROM license_keys WHERE key = ?", (key,))
    except Exception as e:
        return JSONResponse(status_code=200, content={"valid": False, "message": f"DB lỗi: {e}", "error": str(e)[:200]})
    if not rs.rows:
        return {"valid": False, "message": "Key không tồn tại"}
    is_active, expires_at = rs.rows[0]
    if not is_active:
        return {"valid": False, "message": "Key đã bị khóa"}
    if expires_at:
        try:
            if datetime.now() > datetime.fromisoformat(expires_at):
                return {"valid": False, "message": f"Key đã hết hạn ({expires_at})"}
        except Exception:
            pass
    return {"valid": True, "message": "OK", "expires": expires_at}


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
    """Upsert the trusted local script set into the configured database."""
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

    new_key = _new_license_key()

    now = datetime.now()
    expires = None

    if req.custom_date:
        try:
            expires = datetime.fromisoformat(req.custom_date).replace(hour=23, minute=59, second=59).isoformat()
        except ValueError:
            raise HTTPException(status_code=400, detail="Định dạng ngày không hợp lệ (YYYY-MM-DD)")
    elif req.hours and req.hours > 0:
        expires = (now + timedelta(hours=req.hours)).isoformat()
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
    
    if req.hours and req.hours > 0:
        duration = timedelta(hours=req.hours)
        duration_text = f"{req.hours} giờ"
    elif req.days and req.days > 0:
        duration = timedelta(days=req.days)
        duration_text = f"{req.days} ngày"
    else:
        raise HTTPException(status_code=400, detail="Cần nhập số giờ hoặc số ngày lớn hơn 0")
    new_expires = (base_date + duration).isoformat()
    
    await client.execute("UPDATE license_keys SET expires_at = ? WHERE key = ?", (new_expires, key))
    
    return {"message": f"Đã gia hạn thêm {duration_text}", "new_expires": new_expires}


@app.post("/api/integrations/aovshop/checkpass-keys")
async def issue_checkpass_key_from_aovshop(req: IssueShopKeyRequest, request: Request):
    """Issue one idempotent, hour-based Checkpass key for a paid AOVshop order."""
    _require_aovshop_issuer(request)
    order_ref = str(req.order_id)
    existing = await client.execute(
        "SELECT key, expires_at FROM license_keys WHERE source=? AND external_order_id=?",
        ("aovshop-checkpass", order_ref),
    )
    if existing.rows:
        return {"key": existing.rows[0][0], "expires_at": existing.rows[0][1], "order_id": req.order_id, "reused": True}

    now = datetime.now()
    expires = (now + timedelta(hours=req.duration_hours)).isoformat()
    key = _new_license_key()
    note = f"Checkpass | AOVshop order #{req.order_id} | product #{req.product_id}"
    if req.customer_email:
        note += f" | {req.customer_email.strip()}"
    try:
        await client.execute(
            """INSERT INTO license_keys (key, created_at, expires_at, max_devices, note, source, external_order_id)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (key, now.isoformat(), expires, 1, note, "aovshop-checkpass", order_ref),
        )
    except Exception:
        # A retry can race with the first request. Return the one winning key rather than issuing a second.
        existing = await client.execute(
            "SELECT key, expires_at FROM license_keys WHERE source=? AND external_order_id=?",
            ("aovshop-checkpass", order_ref),
        )
        if existing.rows:
            return {"key": existing.rows[0][0], "expires_at": existing.rows[0][1], "order_id": req.order_id, "reused": True}
        raise
    return {"key": key, "expires_at": expires, "order_id": req.order_id, "reused": False}

@app.get("/api/admin/keys")
async def list_keys(admin_password: str, response: Response):
    """Danh sách tất cả key."""
    check_admin(admin_password)

    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
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


@app.delete("/api/admin/keys/{key}/purge")
async def purge_key(key: str, admin_password: str):
    """Permanently delete a key. This cannot be undone."""
    check_admin(admin_password)
    rs = await client.execute("SELECT key FROM license_keys WHERE key = ?", (key,))
    if not rs.rows:
        raise HTTPException(status_code=404, detail="Key không tồn tại")
    await client.execute("DELETE FROM license_keys WHERE key = ?", (key,))
    return {"message": f"Đã xóa vĩnh viễn key {key}"}

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

  .script-upload { display: flex; gap: 12px; flex-wrap: wrap; align-items: center; }
  .script-upload input[type="file"] {
    flex: 1;
    min-width: 260px;
    padding: 8px;
    border: 1px dashed #555;
    border-radius: 6px;
    background: #16213e;
    color: #ddd;
  }
  .muted { color: #888; font-size: 0.82em; margin-top: 10px; line-height: 1.5; }
  .hash-text { font-family: Consolas, monospace; color: #aaa; }

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
            <option value="hours:1">1 giờ</option>
            <option value="hours:6">6 giờ</option>
            <option value="hours:12">12 giờ</option>
            <option value="hours:24">24 giờ</option>
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

    <!-- Script resources -->
    <div class="card">
      <h2>☁️ Script Server (<span id="scriptCount">0</span>)</h2>
      <div class="script-upload">
        <input type="file" id="scriptFiles" accept=".json,application/json" multiple>
        <label><input type="checkbox" id="replaceAllScripts" checked> Khóa script cũ không được chọn</label>
        <button id="uploadScriptsBtn" class="btn btn-primary" onclick="uploadScripts()">Upload scripts</button>
      </div>
      <p class="muted">
        Chọn nhiều file JSON cùng lúc. Mỗi file phải là một danh sách action; dữ liệu được lưu trong database,
        không đưa vào GitHub. Tổng dung lượng một lần upload tối đa 2 MB.
      </p>
      <table style="margin-top:12px">
        <thead><tr><th>Tên script</th><th>SHA-256</th><th>Cập nhật</th><th>Trạng thái</th></tr></thead>
        <tbody id="scriptTable"></tbody>
      </table>
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
    const res = await fetch(`${API}/api/admin/keys?admin_password=${encodeURIComponent(ADMIN_PASS)}&_=${Date.now()}`, { cache: 'no-store' });
    if (res.status === 403) { toast('Sai mật khẩu!', 'error'); return; }
    document.getElementById('loginScreen').classList.add('hidden');
    document.getElementById('adminPanel').classList.remove('hidden');
    loadKeys();
    loadScripts();
  } catch(e) {
    toast('Lỗi kết nối server', 'error');
  }
}

// Older keys were stored as UTC ISO strings without a timezone suffix.
// Treat those values as UTC, then always render them in Vietnam time.
function parseKeyDate(value) {
  if (!value) return null;
  const text = String(value);
  const hasTimezone = /(?:Z|[+-]\\d{2}:\\d{2})$/i.test(text);
  return new Date(hasTimezone ? text : `${text}Z`);
}

function formatVietnamDate(value) {
  const date = parseKeyDate(value);
  if (!date || Number.isNaN(date.getTime())) return String(value || '—');
  return date.toLocaleString('vi-VN', {
    timeZone: 'Asia/Ho_Chi_Minh',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  });
}

async function loadKeys() {
  const res = await fetch(`${API}/api/admin/keys?admin_password=${encodeURIComponent(ADMIN_PASS)}&_=${Date.now()}`, { cache: 'no-store' });
  const keys = await res.json();
  document.getElementById('keyCount').textContent = keys.length;

  const tbody = document.getElementById('keyTable');
  tbody.innerHTML = '';

  keys.forEach(k => {
    const expiresDate = parseKeyDate(k.expires_at);
    const isExpired = expiresDate && !Number.isNaN(expiresDate.getTime()) && expiresDate < new Date();
    let status = '';
    if (!k.is_active) status = '<span class="badge badge-inactive">Đã khóa</span>';
    else if (isExpired) status = '<span class="badge badge-expired">Hết hạn</span>';
    else status = '<span class="badge badge-active">Hoạt động</span>';

    const expires = k.expires_at ? formatVietnamDate(k.expires_at) : 'Vĩnh viễn';
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
            <button class="btn btn-danger btn-sm" onclick="purgeKey('${k.key}')">Xóa hẳn</button>
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

async function loadScripts() {
  const res = await fetch(`${API}/api/admin/scripts?admin_password=${encodeURIComponent(ADMIN_PASS)}`);
  if (!res.ok) {
    document.getElementById('scriptTable').innerHTML = '<tr><td colspan="4">Không thể tải danh sách script</td></tr>';
    return;
  }
  const scripts = await res.json();
  document.getElementById('scriptCount').textContent = scripts.filter(s => s.is_active).length;
  const tbody = document.getElementById('scriptTable');
  tbody.innerHTML = '';
  scripts.forEach(script => {
    const row = document.createElement('tr');
    const updated = script.updated_at ? new Date(script.updated_at).toLocaleString('vi-VN') : '—';
    const status = script.is_active
      ? '<span class="badge badge-active">Hoạt động</span>'
      : '<span class="badge badge-inactive">Đã khóa</span>';
    row.innerHTML = `
      <td>${script.name}</td>
      <td><span class="hash-text" title="${script.sha256}">${script.sha256.substring(0, 12)}...</span></td>
      <td>${updated}</td>
      <td>${status}</td>`;
    tbody.appendChild(row);
  });
  if (!scripts.length) {
    tbody.innerHTML = '<tr><td colspan="4">Chưa có script trên server</td></tr>';
  }
}

async function uploadScripts() {
  const input = document.getElementById('scriptFiles');
  const files = Array.from(input.files || []);
  if (!files.length) { toast('Hãy chọn ít nhất một file JSON', 'error'); return; }
  if (files.reduce((sum, file) => sum + file.size, 0) > 2 * 1024 * 1024) {
    toast('Tổng dung lượng scripts vượt quá 2 MB', 'error'); return;
  }
  const seen = new Set();
  const scripts = [];
  try {
    for (const file of files) {
      if (!/^[A-Za-z0-9_. -]{1,128}\\.json$/.test(file.name) || file.name.includes('..')) {
        throw new Error(`Tên file không hợp lệ: ${file.name}`);
      }
      if (seen.has(file.name)) throw new Error(`Trùng tên file: ${file.name}`);
      seen.add(file.name);
      const content = JSON.parse(await file.text());
      if (!Array.isArray(content) || !content.every(item => item && typeof item === 'object' && !Array.isArray(item))) {
        throw new Error(`${file.name} phải chứa một danh sách object JSON`);
      }
      scripts.push({name: file.name, content});
    }
  } catch (error) {
    toast(error.message || 'File script không hợp lệ', 'error'); return;
  }

  const button = document.getElementById('uploadScriptsBtn');
  button.disabled = true;
  button.textContent = 'Đang upload...';
  try {
    const res = await fetch(`${API}/api/admin/scripts/sync`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        admin_password: ADMIN_PASS,
        scripts,
        replace_all: document.getElementById('replaceAllScripts').checked
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Server từ chối upload');
    toast(`Đã đồng bộ ${data.synced} scripts`);
    input.value = '';
    await loadScripts();
  } catch (error) {
    toast(error.message || 'Upload scripts thất bại', 'error');
  } finally {
    button.disabled = false;
    button.textContent = 'Upload scripts';
  }
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
  let hours = null;
  let custom_date = null;

  if (type === 'custom') {
    custom_date = document.getElementById('keyCustomDate').value;
    if (!custom_date) { toast('Vui lòng chọn ngày!', 'error'); return; }
  } else if (type.startsWith('hours:')) {
    hours = parseInt(type.slice(6)) || null;
  } else {
    days = parseInt(type) || null;
  }
  
  const note = document.getElementById('keyNote').value;

  const res = await fetch(`${API}/api/admin/keys`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ admin_password: ADMIN_PASS, days, hours, custom_date, note })
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
  const duration = prompt(`Gia hạn cho key ${key}. Nhập 6h (giờ) hoặc 30d (ngày):`, "30d");
  if (duration === null || duration === "") return;
  const match = String(duration).trim().match(/^(\\d+)\\s*([hHdD])$/);
  if (!match || Number(match[1]) < 1) { toast('Nhập dạng 6h hoặc 30d', 'error'); return; }
  const amount = parseInt(match[1]);
  const payload = match[2].toLowerCase() === 'h' ? {hours: amount} : {days: amount};

  const res = await fetch(`${API}/api/admin/keys/${key}/extend`, {
    method: 'PUT',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ admin_password: ADMIN_PASS, ...payload })
  });
  
  if (res.ok) {
    toast(`Đã gia hạn thêm ${duration}`);
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

async function purgeKey(key) {
  if (!confirm(`XÓA VĨNH VIỄN key ${key}? Không thể khôi phục.`)) return;
  const res = await fetch(`${API}/api/admin/keys/${key}/purge?admin_password=${encodeURIComponent(ADMIN_PASS)}`, { method: 'DELETE' });
  if (!res.ok) { const err = await res.json(); toast(err.detail || 'Không thể xóa key', 'error'); return; }
  toast('Đã xóa vĩnh viễn key');
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
