# Vault — Kho Mật Khẩu

Ứng dụng quản lý mật khẩu dùng Cloudflare Pages + KV.

## Cấu trúc
```
vault-new/
├── functions/api/vault.js   ← Cloudflare Pages Function (API)
├── index.html               ← Giao diện chính
├── _headers                 ← Security headers
└── README.md
```

## Kiến trúc (hết lỗi cross-browser)
- **Không có client-side encryption** — password chỉ dùng để xác thực API
- Data lưu plaintext JSON trong Cloudflare KV
- Giống cách nekowo.site/password hoạt động với PHP
- Mọi trình duyệt đọc cùng 1 nguồn dữ liệu → không bao giờ bị "Sai mật khẩu"

## Deploy lên Cloudflare Pages

### Bước 1: Push lên GitHub
```bash
git init
git add .
git commit -m "vault init"
git remote add origin https://github.com/your/repo.git
git push -u origin main
```

### Bước 2: Tạo Pages project
- CF Dashboard → Pages → Create project → Connect to Git → chọn repo
- Build settings: để trống (không cần build)
- Output directory: để trống (hoặc `/`)

### Bước 3: Tạo KV namespace
- CF Dashboard → Workers & Pages → KV → Create namespace
- Đặt tên: `VAULT_KV`

### Bước 4: Bind KV vào Pages
- CF Dashboard → Pages → [project] → Settings → Functions
- KV namespace bindings → Add:
  - Variable name: `VAULT_KV`
  - KV namespace: chọn `VAULT_KV` vừa tạo

### Bước 5: Redeploy
- Vào Deployments → Retry deployment (hoặc push 1 commit mới)

## Lần đầu dùng
1. Vào trang web
2. Nhập mật khẩu bất kỳ → hệ thống tự tạo kho mới với mật khẩu đó
3. Lần sau chỉ cần nhập đúng mật khẩu đó là vào được từ bất kỳ trình duyệt nào

## Tính năng
- ✅ Hỗ trợ Discord (với 2FA/TOTP)
- ✅ Hỗ trợ Roblox (với Cookie .ROBLOSECURITY)
- ✅ Sinh mã TOTP trực tiếp (đếm ngược 30s)
- ✅ Các danh mục: Discord, Roblox, Email, Mạng xã hội, Game, Khác
- ✅ Tìm kiếm realtime
- ✅ Copy mật khẩu / username / cookie / mã 2FA
- ✅ Đồng bộ cloud — mọi trình duyệt xem cùng 1 kho
