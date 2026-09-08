# License Key Server (PostgreSQL / SQLite Edition)

Server API quản lý license key cho ToolAOV, sử dụng PostgreSQL trên VPS (hoặc
SQLite local khi phát triển) và token Ed25519 ngắn hạn. Mỗi phản hồi xác thực
được ký kèm key, HWID, nonce và hạn token.

## Cài đặt

```bash
cd license_server
pip install -r requirements.txt
```

## Cấu hình PostgreSQL

Trên VPS, tạo database và user PostgreSQL, sau đó cấu hình:

```text
DATABASE_URL=postgresql://license_user:mat_khau@127.0.0.1:5432/license_db
```

Server sẽ tự tạo các bảng `license_keys` và `flow_scripts` khi khởi động.

## Chạy server

### Local (Dùng SQLite local làm fallback)
Nếu không set `DATABASE_URL`, server tự tạo file `license.db` local.
```bash
uvicorn server:app --reload --host 0.0.0.0 --port 8000
```

### Production (Dùng PostgreSQL trên VPS)
Set các biến môi trường trước khi chạy:
```bash
# Windows
set ADMIN_PASSWORD=matkhau_cua_ban
set DATABASE_URL=postgresql://license_user:mat_khau@127.0.0.1:5432/license_db
uvicorn server:app --host 0.0.0.0 --port 8000

# Linux (VPS)
ADMIN_PASSWORD=xxx DATABASE_URL=postgresql://license_user:mat_khau@127.0.0.1:5432/license_db uvicorn server:app --host 0.0.0.0 --port 8000
```

Hoặc deploy lên **Render.com** (free):
1. Push code lên GitHub
2. Tạo Web Service trên Render
3. Build command: `pip install -r requirements.txt`
4. Start command: `uvicorn server:app --host 0.0.0.0 --port $PORT`
5. Thêm Environment Variable: `ADMIN_PASSWORD`

## Biến ký token bắt buộc

Ngoài cấu hình database, production bắt buộc có:

```text
LICENSE_SIGNING_PRIVATE_KEY=<Ed25519 private key base64>
```

Private key đã tạo cho bản client hiện tại nằm trong file `.env` cục bộ (file
này được `.gitignore`). Sao chép giá trị đó vào Environment của Render, tuyệt
đối không commit hoặc gửi kèm bản ToolAOV. Public key tương ứng đã được nhúng
trong client nên khi đổi key pair phải build lại client.

`POST /api/verify` hiện yêu cầu `key`, `hwid`, `nonce` và trả thêm token ký số
có hiệu lực 5 phút. Client cũ chưa gửi nonce sẽ không còn tương thích.

## Script resources

The server creates a `flow_scripts` table in PostgreSQL/SQLite automatically. Script JSON is
uploaded through `POST /api/admin/scripts/sync`; it is not stored in this Git
repository. `POST /api/scripts/bundle` requires an active license already bound
to the submitted HWID and returns a signed in-memory bundle. Before every script
run, the client calls `POST /api/scripts/{name}/authorize` for a short-lived signed
ticket bound to the key hash, HWID, nonce, script name, and canonical content hash.

Deploy this server version before synchronizing scripts or releasing the matching
client. Icons remain packaged locally and are not stored by these endpoints.
