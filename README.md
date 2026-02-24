# License Key Server (Turso / libSQL Edition)

Server API quản lý license key cho tool Garena Account Manager, sử dụng Turso (libSQL) để lưu trữ cloud cực nhanh.

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
