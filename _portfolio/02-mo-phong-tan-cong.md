---
title: "Mô phỏng tấn công tự động và kiểm thử thủ công"
excerpt: "Kiểm thử bằng công cụ tự động (Atomic Red Team và tương tự) kết hợp kiểm thử thủ công với Metasploit, msfvenom, Nessus, Burp Suite, dựa trên các kỹ thuật MITRE ATT&CK. **Trạng thái: hoàn thành.**"
collection: portfolio
order: 2
---

**Trạng thái:** Hoàn thành

## Mục tiêu
Tạo ra hành vi tấn công có kiểm soát để kiểm tra khả năng phát hiện của hệ thống giám sát, dựa trên các kỹ thuật có trong **MITRE ATT&CK**.

## Kiểm thử tự động (Automated Red Team)
- **Atomic Red Team** (Invoke-AtomicRedTeam) chạy từng "atomic test" theo mã kỹ thuật ATT&CK
- **MITRE Caldera** mô phỏng đối thủ theo kịch bản
- **Stratus Red Team** (mô phỏng kỹ thuật tấn công trên môi trường cloud)
- **Infection Monkey** (mô phỏng xâm nhập và di chuyển ngang)

## Kiểm thử thủ công
- **Metasploit** và **msfvenom** (khai thác và tạo payload)
- **Nessus** (quét lỗ hổng)
- **Burp Suite** (kiểm thử ứng dụng web)

## Kết quả
Mỗi kỹ thuật được thực thi đều đối chiếu với log và alert trên SIEM để biết phát hiện được hay còn bỏ sót.
