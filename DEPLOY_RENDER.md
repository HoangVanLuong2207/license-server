# 🚀 Hướng dẫn Deploy License Server lên Render.com

Chào bạn, Render là một lựa chọn **tuyệt vời** và cực kỳ dễ dàng để chạy Python FastAPI server. Dưới đây là lộ trình "thực chiến" để bạn đưa server này lên online.

## 🛠️ Bước 1: Chuẩn bị Repository
1. **GitHub**: Tạo một Repo mới (để Private nếu bạn không muốn lộ code).
2. **Push Code**: Đẩy toàn bộ nội dung thư mục `license_server/` lên repo này.
   - Đảm bảo file `server.py` và `requirements.txt` nằm ở thư mục gốc của Repo.
   - Đừng quên file `requirements.txt` phải chứa các thư viện: `fastapi`, `uvicorn[standard]`, `libsql-client`.

## 🌐 Bước 2: Khởi tạo Web Service trên Render
1. Truy cập [Render Dashboard](https://dashboard.render.com).
2. Chọn **New +** -> **Web Service**.
3. Kết nối với tài khoản GitHub và chọn Repo vừa tạo.
4. Cấu hình các thông số quan trọng:
   - **Name**: `garena-license-server` (hoặc tên tùy ý).
   - **Region**: Chọn **Singapore (Southeast Asia)** để có tốc độ tốt nhất về Việt Nam.
   - **Runtime**: `Python 3`.
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn server:app --host 0.0.0.0 --port $PORT`
   - **Instance Type**: `Free` (Vừa đủ cho nhu cầu cơ bản).

## 🔐 Bước 3: Cấu hình Biến môi trường (QUAN TRỌNG)
Vào tab **Environment** trong trang quản lý của Render và thêm các biến (Variables) sau:

| Key | Value | Ghi chú |
|:--- |:--- |:--- |
| `ADMIN_PASSWORD` | `Mật-khẩu-của-bạn` | Dùng để đăng nhập vào trang Admin Panel. |
| `TURSO_URL` | `libsql://your-db-name.turso.io` | Copy từ Dashboard của Turso. |
| `TURSO_AUTH_TOKEN` | `ey...your-token...` | Token dùng để kết nối Database. |

> [!IMPORTANT]
> Nếu bạn không cấu hình `TURSO_URL`, server sẽ tự động tạo file `license.db` ngay trên Render. Tuy nhiên, ở bản **Free**, file này sẽ bị **XÓA SẠCH** mỗi khi server restart. **Bắt buộc dùng Turso để lưu dữ liệu vĩnh viễn.**

## 📈 Bước 4: Kiểm tra và Kết nối
1. Sau khi Render báo **"Live"**, copy URL của bạn (VD: `https://garena-license.onrender.com`).
2. **Test Admin**: Truy cập URL đó trên trình duyệt, đăng nhập bằng `ADMIN_PASSWORD` bạn đã set.
3. **Cập nhật Client**: Quay lại tool Python của bạn, đổi URL gọi API thành URL mới này.

---

### ⚠️ Lưu ý về Render Free Tier (Cold Start)
- Render Free sẽ "đi ngủ" sau 15 phút không có ai dùng. 
- Lần truy cập đầu tiên sau khi ngủ sẽ mất khoảng **30-50 giây** để khởi động lại.
- **Mẹo**: Nếu muốn server luôn thức, bạn có thể dùng dịch vụ ping miễn phí như [cron-job.org](https://cron-job.org/) để ping URL của bạn 10-15 phút/lần.

