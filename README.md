# Portfolio - Võ Quốc Huy

Website portfolio xây dựng từ template [Academic Pages](https://github.com/academicpages/academicpages.github.io) (Jekyll + GitHub Pages).

## Đưa lên GitHub Pages
1. Tạo repo **public** tên `huyvo13032005.github.io` trên tài khoản GitHub của bạn.
2. Đẩy toàn bộ thư mục này lên nhánh `master`:
   ```bash
   git init
   git add .
   git commit -m "Initial portfolio"
   git branch -M master
   git remote add origin https://github.com/huyvo13032005/huyvo13032005.github.io.git
   git push -u origin master
   ```
3. Vào **Settings → Pages → Build and deployment → Source** chọn **GitHub Actions**.
4. Đợi workflow chạy xong (tab Actions), website sẽ ở `https://huyvo13032005.github.io`.

## Chỉnh sửa nội dung
| Muốn sửa | File |
|---|---|
| Thông tin sidebar, link GitHub/LinkedIn... | `_config.yml` (mục `author`) |
| Menu trên cùng | `_data/navigation.yml` |
| Trang giới thiệu | `_pages/about.md` |
| CV | `_pages/cv.md` |
| Chứng chỉ | `_pages/certifications.md` |
| Dự án | `_portfolio/*.md` (mỗi dự án một file, `order` quyết định thứ tự) |
| Ảnh đại diện | thay `images/profile.png` |
| File PDF (CV, chứng chỉ) | bỏ vào `files/`, link dạng `/files/ten-file.pdf` |

Chạy thử trên máy: `bundle install` rồi `bundle exec jekyll serve`, mở http://localhost:4000
