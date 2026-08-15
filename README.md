# License Key Server (Turso / libSQL Edition)

Server API quản lý license key cho ToolAOV, sử dụng Turso (libSQL) và token
Ed25519 ngắn hạn. Mỗi phản hồi xác thực được ký kèm key, HWID, nonce và hạn token.

## Cài đặt

```bash
cd license_server
pip install -r requirements.txt
```

## Cấu hình Turso

Bạn cần tạo database trên [Turso.tech](https://turso.tech) và lấy:
1. **Turso URL** (VD: `libsql://your-db.turso.io`)
2. **Auth Token** (API Token)

## Chạy server

### Local (Dùng SQLite local làm fallback)
Nếu không set Turso biến môi trường, server tự tạo file `license.db` local.
```bash
uvicorn server:app --reload --host 0.0.0.0 --port 8000
```

### Production (Dùng Turso Cloud)
Set các biến môi trường trước khi chạy:
```bash
# Windows
set ADMIN_PASSWORD=matkhau_cua_ban
set TURSO_URL=libsql://your-db-name.turso.io
set TURSO_AUTH_TOKEN=your_token_here
uvicorn server:app --host 0.0.0.0 --port 8000

# Linux (VPS)
ADMIN_PASSWORD=xxx TURSO_URL=xxx TURSO_AUTH_TOKEN=xxx uvicorn server:app --host 0.0.0.0 --port 8000
```

Hoặc deploy lên **Render.com** (free):
1. Push code lên GitHub
2. Tạo Web Service trên Render
3. Build command: `pip install -r requirements.txt`
4. Start command: `uvicorn server:app --host 0.0.0.0 --port $PORT`
5. Thêm Environment Variable: `ADMIN_PASSWORD`

## Biến ký token bắt buộc

Ngoài cấu hình Turso, production bắt buộc có:

```text
LICENSE_SIGNING_PRIVATE_KEY=<Ed25519 private key base64>
```

Private key đã tạo cho bản client hiện tại nằm trong file `.env` cục bộ (file
này được `.gitignore`). Sao chép giá trị đó vào Environment của Render, tuyệt
đối không commit hoặc gửi kèm bản ToolAOV. Public key tương ứng đã được nhúng
trong client nên khi đổi key pair phải build lại client.

`POST /api/verify` hiện yêu cầu `key`, `hwid`, `nonce` và trả thêm token ký số
có hiệu lực 5 phút. Client cũ chưa gửi nonce sẽ không còn tương thích.
