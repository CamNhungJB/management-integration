# backend/services/rule_generator.py
import sys,os
sys.path.append(os.path.dirname(__file__))
import tempfile
import sqlite3
from datetime import datetime
import config
from services.abuseipdb_service import save_ips_to_file
from services.threatfox_service import process_threatfox
from services.db_service import ensure_sqlite, create_new_rule_set, insert_rules_batch, set_active_rule_set
import services.db_service
def generate_threatfox_rules(cur):
    """Sinh rule từ bảng IOC có source = ThreatFox"""
    cur.execute("""
        SELECT ioc, ioc_type, sid, confidence, meta
        FROM ioc
        WHERE source = 'ThreatFox'
        ORDER BY updated_at DESC
    """)
    rows = cur.fetchall()
    rules_data = []

    for (ioc, ioc_type, sid, conf, meta) in rows:
        comment = f"\"ThreatFox | conf={conf}\""
        rule_content = ""
        if ioc_type == "ip":
            rule_content = (
                f'alert ip any any -> {ioc} any '
                f'(msg:{comment}; sid:{sid}; rev:1;  priority:2;)'
            )
        elif ioc_type == "domain":
            rule_content = (
                f'alert tcp any any -> any 80 '
                f'(msg:{comment}; content:"Host|3A| {ioc}"; http_header; '
                f'sid:{sid}; rev:1;  priority:2;)'           
            )
        if rule_content:
            # MỚI: Thêm vào danh sách dưới dạng dict
            rules_data.append({
                "content": rule_content,
                "source": "threatfox",
                "threat_id": f"{ioc_type}:{ioc}"
            })
    return rules_data


def generate_abuseipdb_rules_from_file(filepath="data/abuseipdb_blacklist.txt", sid_base=3000000):
    """
    Sinh rule từ danh sách IP trong file blacklist.
    Không dùng DB, chỉ đọc từ file text.
    """
    if not os.path.exists(filepath):
        print(f"[!] File {filepath} không tồn tại → bỏ qua AbuseIPDB rules.")
        return []

    with open(filepath) as f:
        ips = [line.strip() for line in f if line.strip()]

    if not ips:
        print(f"[!] File {filepath} rỗng → không có IP để sinh rule.")
        return []

    rules_data = []
    for i, ip in enumerate(ips):
        sid = sid_base + i
        comment = f"\"AbuseIPDB blacklist | {ip}\""
        rule_content = (
            f'alert ip any any -> {ip} any '
            f'(msg:{comment}; sid:{sid}; rev:1; priority:1; '
            f'metadata:source AbuseIPDB; '
            f'reference:url,https://www.abuseipdb.com/check/{ip};)'
        )
        rules_data.append({
            "content": rule_content,
            "source": "abuseipdb",
            "threat_id": f"ip:{ip}"
        })

    print(f"[+] Generated {len(rules_data)} AbuseIPDB rules from {filepath}")
    return rules_data

def publish_rules_to_mongo():
    """
    MỚI: Đây là hàm "main" mới, thay thế cho generate_rules() cũ.
    Quy trình: Sinh rules -> Đẩy lên MongoDB theo 3 bước.
    """
    conn = ensure_sqlite() # Dùng hàm ensure_sqlite để lấy conn
    cur = conn.cursor()

    print("[*] Bắt đầu quá trình sinh và publish rule lên MongoDB...")
    all_rules_data = []

    # --- Bước 1: Sinh rule từ các nguồn ---
    threatfox_rules = generate_threatfox_rules(cur)
    print(f"[+] {len(threatfox_rules)} rule từ ThreatFox.")
    all_rules_data.extend(threatfox_rules)

    abuseipdb_rules = generate_abuseipdb_rules_from_file()
    all_rules_data.extend(abuseipdb_rules)

    conn.close()

    total_rules = len(all_rules_data)
    if total_rules == 0:
        print("[!] Không có rule nào được sinh ra. Dừng publish.")
        return 0

    print(f"[+] Tổng cộng {total_rules} rule được sinh ra.")

    # --- Bước 2: Publish lên MongoDB ---
    try:
        # 2a. Tạo Rule Set (Metadata)
        version_name = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        description = f"Cập nhật tự động: {len(threatfox_rules)} ThreatFox, {len(abuseipdb_rules)} AbuseIPDB"
        sources = ["threatfox", "abuseipdb"]
        
        new_set_id = create_new_rule_set(
            version_name, description, total_rules, sources
        )

        # 2b. Chèn hàng loạt các rule
        insert_rules_batch(all_rules_data, new_set_id)

        # 2c. Kích hoạt phiên bản mới
        set_active_rule_set(new_set_id)

        print(f"[✓] HOÀN TẤT: Đã publish thành công Rule Set '{version_name}' (ID: {new_set_id})")

        return {
            "rule_set_id": str(new_set_id),
            "version": version_name,
            "total_rules": total_rules
        }

    except Exception as e:
        print(f"[!!!] LỖI NGHIÊM TRỌNG khi publish lên MongoDB: {e}")
        print("[!] Phiên bản active rule set KHÔNG BỊ THAY ĐỔI. Vui lòng kiểm tra log.")
        # Bạn có thể thêm logic dọn dẹp (xóa rule_set vừa tạo) ở đây nếu muốn
        return 0


# MỚI: Thêm entry point để có thể chạy file này trực tiếp
if __name__ == "__main__":
    # Dòng này sẽ chạy toàn bộ quy trình
    publish_rules_to_mongo()

def generate_rules():
    """Sinh toàn bộ rule (ThreatFox + AbuseIPDB)"""
    conn = sqlite3.connect(config.SQLITE_DB)
    cur = conn.cursor()

    print("[*] Generating rules...")
    rules = []

    # ThreatFox từ DB
    threatfox_rules = generate_threatfox_rules(cur)
    print(f"[+] {len(threatfox_rules)} ThreatFox rules generated.")
    rules += threatfox_rules

    # AbuseIPDB từ file
    abuseipdb_rules = generate_abuseipdb_rules_from_file()
    rules += abuseipdb_rules

    # Ghi ra file tạm (atomic write)
    os.makedirs(os.path.dirname(config.RULE_FILE), exist_ok=True)
    tmp = tempfile.NamedTemporaryFile("w", delete=False)

    header = f"# Rules generated at {datetime.utcnow().isoformat()}Z\n"
    tmp.write(header)
    tmp.write(f"# Total rules: {len(rules)}\n\n")

    for line in rules:
        tmp.write(line + "\n")

    tmp.flush()
    os.replace(tmp.name, config.RULE_FILE)
    conn.close()

    print(f"[✓] Wrote {len(rules)} total rules to {config.RULE_FILE}")
    return len(rules)
