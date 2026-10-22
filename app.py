import streamlit as st
import json

st.title("🛡️ Hệ thống Giám sát An ninh Mạng")
st.subheader("Bảng điều khiển cảnh báo đăng nhập bất thường")

try:
    # 1. Đọc file JSON
    with open("data/sample_logs.json", "r", encoding="utf-8") as f:
        logs = json.load(f)
    
    st.write(f"Đã đọc thành công {len(logs)} dòng log từ file.")

    # 2. Kiểm tra validator trực tiếp tại đây luôn cho chắc ăn
    valid_logs = []
    for log in logs:
        # Kiểm tra trường bắt buộc
        if log.get("timestamp") and log.get("username") and log.get("source_ip") and log.get("event_type"):
            valid_logs.append(log)

    st.metric(label="Số sự kiện hợp lệ sau khi lọc", value=len(valid_logs))

    # 3. Thuật toán phát hiện Brute-force trực tiếp
    ip_failed_counts = {}
    alerts = []
    alerted_ips = []

    for entry in valid_logs:
        if entry.get("event_type") == "login_failed":
            ip = entry.get("source_ip")
            ip_failed_counts[ip] = ip_failed_counts.get(ip, 0) + 1
            
            # Cứ từ 5 lần thất bại trở lên là báo động
            if ip_failed_counts[ip] >= 5 and ip not in alerted_ips:
                alerts.append({
                    "rule_id": "R1",
                    "severity": "HIGH",
                    "source_ip": ip,
                    "message": f"Cảnh báo: IP {ip} đăng nhập thất bại {ip_failed_counts[ip]} lần (Brute-force)!"
                })
                alerted_ips.append(ip)

    # 4. Hiển thị cảnh báo lên giao diện
    st.write("### 🚨 Danh sách Cảnh báo Phát hiện được:")
    if alerts:
        for alert in alerts:
            st.error(f"[{alert['rule_id']}] {alert['message']} - Mức độ: {alert['severity']}")
    else:
        st.warning("Không tìm thấy cảnh báo nào thỏa mãn điều kiện.")

    # Hiển thị bảng dữ liệu thô để kiểm tra
    st.write("### 📋 Dữ liệu Log chi tiết:")
    st.json(valid_logs)

except Exception as e:
    st.error(f"Lỗi xảy ra: {e}")