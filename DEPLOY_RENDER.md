# Deploy License Server lên VPS với PostgreSQL

Tài liệu này thay thế hướng dẫn triển khai dịch vụ cloud cũ. Ứng dụng dùng
PostgreSQL trên chính VPS thông qua `DATABASE_URL` và không cần database bên thứ ba.

## 1. Tạo database

Trên Ubuntu/Debian có PostgreSQL, chạy:

```bash
sudo -u postgres psql
```

```sql
CREATE USER license_user WITH PASSWORD 'thay-bang-mat-khau-manh';
CREATE DATABASE license_db OWNER license_user;
\q
```

Không public cổng PostgreSQL ra Internet; ứng dụng và PostgreSQL cùng VPS nên
dùng địa chỉ `127.0.0.1`.

## 2. Cấu hình ứng dụng

Tạo `/etc/license-server.env`:

```env
ADMIN_PASSWORD=mat-khau-admin-rat-dai
DATABASE_URL=postgresql://license_user:thay-bang-mat-khau-manh@127.0.0.1:5432/license_db
LICENSE_SIGNING_PRIVATE_KEY=ed25519-private-key-base64
```

Server tự tạo bảng ở lần khởi động đầu tiên. Không đưa file này lên GitHub.

## 3. Cài và chạy

```bash
cd /opt/license-server
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Tạo systemd service với `EnvironmentFile=/etc/license-server.env` và:

```ini
ExecStart=/opt/license-server/.venv/bin/uvicorn server:app --host 127.0.0.1 --port 8000
```

Dùng Nginx để proxy HTTPS từ domain về `127.0.0.1:8000`. Kiểm tra hoạt động:

```bash
curl http://127.0.0.1:8000/ping
sudo journalctl -u license-server -f
```

## Sao lưu

Sao lưu PostgreSQL định kỳ:

```bash
pg_dump -h 127.0.0.1 -U license_user -Fc license_db > license-$(date +%F).dump
```
