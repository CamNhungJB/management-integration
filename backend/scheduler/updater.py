# backend/scheduler/updater.py

import time
from datetime import datetime
from services import threatfox_service, abuseipdb_service
from services.rule_generator import publish_rules_to_mongo
from services.db_service import get_mongo_db
import config

DAYS = 2                # khoảng thời gian giữa mỗi lần update
CHECK_INTERVAL = 3600   # mỗi 1 giờ kiểm tra lại


def cleanup_old_rule_sets():
    db = get_mongo_db()
    rule_sets = db[config.MONGO_COL_RULE_SETS]
    rules = db[config.MONGO_COL_RULES]

    all_sets = list(rule_sets.find().sort("timestamp", -1))

    if len(all_sets) <= 2:
        return

    to_delete = all_sets[2:]

    for rs in to_delete:
        rs_id = rs["_id"]
        print(f"🧹 Xoá rule_set cũ: {rs_id}")

        rule_sets.delete_one({"_id": rs_id})
        deleted = rules.delete_many({"rule_set_id": rs_id})

        print(f" - Đã xoá {deleted.deleted_count} rule thuộc rule_set này")


def background_data_updater():
    """
    Chạy vòng lặp:
    - Nếu đã hơn 2 ngày → tự động fetch dữ liệu & sinh rule mới
    - Chỉ chạy 1 lần duy nhất trên 1 instance
    """
    db = get_mongo_db()
    status_col = db["system_status"]

    while True:
        now = datetime.utcnow()
        status = status_col.find_one({"_id": "rule_update_status"})
        last_update = status["last_update"] if status else None

        need_update = (
            last_update is None or
            (now - last_update).total_seconds() >= DAYS * 24 * 3600
        )

        if need_update:
            print("🚀 BẮT ĐẦU cập nhật dữ liệu ThreatFox + AbuseIPDB + Sinh Rule Set mới")

            # 1) Fetch ThreatFox
            try:
                tf = threatfox_service.process_threatfox()
                print(f"✓ ThreatFox inserted: {tf.get('inserted')}")
            except Exception as e:
                print("[X] Lỗi ThreatFox:", e)

            # 2) Fetch AbuseIPDB
            try:
                fp = abuseipdb_service.save_ips_to_file()
                print(f"✓ AbuseIPDB saved: {fp}")
            except Exception as e:
                print("[X] Lỗi AbuseIPDB:", e)

            # 3) Generate Rule Set
            try:
                result = publish_rules_to_mongo()
                print("🔥 Rule Set mới:", result)
            except Exception as e:
                print("[X] Lỗi tạo rule:", e)

            # 4) Cleanup
            try:
                cleanup_old_rule_sets()
                print("🧹 Cleanup hoàn tất")
            except Exception as e:
                print("[X] Lỗi cleanup:", e)

            # 5) Lưu lại thời điểm update
            status_col.update_one(
                {"_id": "rule_update_status"},
                {"$set": {"last_update": now}},
                upsert=True
            )

            print("✓ HOÀN TẤT CẬP NHẬT!\n")

        else:
            remain_hours = int(
                (DAYS * 24 * 3600 - (now - last_update).total_seconds()) / 3600
            )
            print(f"⏳ Chưa đủ {DAYS} ngày — còn {remain_hours} giờ nữa.")

        time.sleep(CHECK_INTERVAL)
