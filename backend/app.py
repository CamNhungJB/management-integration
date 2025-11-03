from flask import Flask, jsonify, request, send_file
from datetime import datetime
from services.threatfox_service import process_threatfox
from services.rule_generator import  publish_rules_to_mongo
from routes.abuseipdb_routes import abuseipdb_bp
from routes.threatfox_routes import threatfox_bp
from routes.rule_routes import rule_bp
from dotenv import load_dotenv
from services import db_service
import json
import config
import os
import threading
import time
from services import threatfox_service, abuseipdb_service
load_dotenv()
app = Flask(__name__)
sensors = {}

@app.route('/api/v1/rules/active_bundle', methods=['GET'])
def get_active_rule_bundle():
    try:
        # 1️⃣ Lấy collection deployment_status
        deploy_col = db_service.get_deployment_status_collection()

        # 2️⃣ Truy vấn _id = "production_sensors"
        deployment = deploy_col.find_one({"_id": "production_sensors"})
        if not deployment or "active_rule_set_id" not in deployment:
            return jsonify({"error": "Không tìm thấy active_rule_set_id"}), 404

        active_id = deployment["active_rule_set_id"]

        # 3️⃣ Lấy collection rules
        rules_col = db_service.get_rules_collection()

        # Nếu ID là ObjectId thì đảm bảo kiểu dữ liệu đúng
        query_id = ObjectId(active_id) if isinstance(active_id, str) and len(active_id) == 24 else active_id

        # 4️⃣ Truy vấn các rule có rule_set_id trùng khớp
        rules_cursor = rules_col.find({"rule_set_id": query_id})
        rules = list(rules_cursor)

        if not rules:
            return jsonify({"error": f"Không tìm thấy rule nào cho rule_set_id {active_id}"}), 404

        # 5️⃣ Gộp nội dung rule
        contents = [r.get("content", "") for r in rules]
        bundle = "\n".join(contents)

        # 6️⃣ Trả kết quả
        return jsonify({
            "active_rule_set_id": str(active_id),
            "bundle": bundle
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/v1/sensors/heartbeat", methods=["POST"])
def sensor_heartbeat():
    try:
        data = request.get_json(force=True)

        # Kiểm tra dữ liệu bắt buộc
        required_fields = ["sensor_id", "hostname", "ip_address", "current_rule_set_id"]
        missing = [f for f in required_fields if f not in data]
        if missing:
            return jsonify({"error": f"Thiếu các trường bắt buộc: {', '.join(missing)}"}), 400

        # Lấy collection sensors
        sensors_col = db_service.get_sensors_collection()

        # Cập nhật hoặc thêm mới sensor
        result = sensors_col.update_one(
            {"_id": data["sensor_id"]},
            {
                "$set": {
                    "last_seen": datetime.utcnow(),
                    "hostname": data["hostname"],
                    "ip_address": data["ip_address"],
                    "current_rule_set_id": data["current_rule_set_id"]
                }
            },
            upsert=True
        )

        # Phản hồi
        if result.upserted_id:
            msg = f"Đã đăng ký sensor mới với ID {data['sensor_id']}"
        else:
            msg = f"Đã cập nhật trạng thái sensor {data['sensor_id']}"

        return jsonify({"message": msg, "sensor_id": data["sensor_id"]}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/v1/rules/publish',  methods=['POST'])
def publish_new_rules():
    """
    API 3: Dành cho Manager - Kích hoạt quá trình sinh và publish rule mới.
    Đây là một tác vụ có thể chạy lâu.
    """
    try:
        # Gọi hàm chính từ rule_generator
        total_rules = publish_rules_to_mongo()
        
        if total_rules > 0:
            return jsonify({
                "status": "success",
                "message": f"Successfully published a new rule set.",
                "total_rules": total_rules
            }), 201 # 201 Created
        else:
            return jsonify({
                "status": "no_action",
                "message": "Không có rule nào được sinh ra hoặc đã có lỗi xảy ra. Vui lòng kiểm tra log.",
                "total_rules": 0
            }), 200

    except Exception as e:
        app.logger.error(f"Error in /publish: {e}")
        return jsonify({"error": f"Failed to publish rules: {str(e)}"}), 500

@app.route("/api/v1/sensors", methods=["GET"])
def list_sensors():
    try:
        sensors_col = db_service.get_sensors_collection()
        rule_sets_col = db_service.get_rule_sets_collection()

        # 1️⃣ Lấy toàn bộ sensor
        sensors = list(sensors_col.find({}))

        if not sensors:
            return jsonify({"sensors": []}), 200

        # 2️⃣ Tạo map rule_set_id → version (để join nhanh)
        rule_sets = {str(rs["_id"]): rs for rs in rule_sets_col.find({})}

        # 3️⃣ Xử lý dữ liệu để trả về cho dashboard
        result = []
        now = datetime.now(timezone.utc)

        for s in sensors:
            sid = s.get("_id")
            rule_set_id = s.get("current_rule_set_id")

            # Lấy thông tin rule version từ rule_sets nếu có
            rule_info = rule_sets.get(str(rule_set_id))
            rule_version = rule_info["version"] if rule_info else "unknown"

            # Tính thời gian kể từ lần seen cuối cùng (để đánh giá trạng thái)
            last_seen = s.get("last_seen")
            if last_seen and isinstance(last_seen, datetime):
                diff = (now - last_seen).total_seconds()
                status = "online" if diff < 600 else "offline"  # 10 phút
            else:
                status = "unknown"

            result.append({
                "sensor_id": sid,
                "hostname": s.get("hostname", ""),
                "ip_address": s.get("ip_address", ""),
                "current_rule_set_id": str(rule_set_id),
                "rule_version": rule_version,
                "last_seen": last_seen.isoformat() if isinstance(last_seen, datetime) else last_seen,
                "status": status
            })

        return jsonify({"sensors": result}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
@app.route('/api/v1/rulesets', methods=['GET'])
def get_rulesets_history():
    """
    API 5: Dành cho Manager - Lấy lịch sử các phiên bản rule đã được publish.
    """
    try:
        rule_sets = db_service.get_all_rule_sets()
        return jsonify(mongo_to_json(rule_sets))
    except Exception as e:
        app.logger.error(f"Error in /rulesets: {e}")
        return jsonify({"error": "An internal server error occurred"}), 500

@app.route('/api/v1/deployment/activate', methods=['POST'])
def activate_rule_set():
    """
    API 6: Dành cho Manager - Rollback, kích hoạt một phiên bản rule cũ.
    """
    data = request.get_json()
    rule_set_id_str = data.get("rule_set_id")

    if not rule_set_id_str:
        return jsonify({"error": "Yêu cầu thiếu 'rule_set_id'"}), 400

    try:
        # Chuyển đổi string sang ObjectId để truy vấn
        rule_set_id = ObjectId(rule_set_id_str)
        
        # Kiểm tra xem rule_set_id này có thực sự tồn tại không
        if not db_service.get_rule_set_by_id(rule_set_id):
            return jsonify({"error": "Rule set with this ID does not exist"}), 404

        # Kích hoạt phiên bản này
        db_service.set_active_rule_set(rule_set_id)
        
        return jsonify({
            "status": "success",
            "message": f"Successfully activated rule set ID: {rule_set_id_str}"
        })
    except Exception as e:
        app.logger.error(f"Error in /deployment/activate: {e}")
        return jsonify({"error": f"Invalid ID format or failed to activate: {str(e)}"}), 500
def background_data_updater():
    """
    Chạy nền, cứ mỗi 2 ngày tự động sinh dữ liệu mới từ ThreatFox và AbuseIPDB.
    """
    INTERVAL = 2 * 24 * 60 * 60  # 2 ngày = 172800 giây

    while True:
        try:
            print("\n[📦] Bắt đầu cập nhật dữ liệu ThreatFox và AbuseIPDB...")

            # 1️⃣ ThreatFox
            try:
                result_threatfox = threatfox_service.process_threatfox()
                print(f"[✓] ThreatFox inserted: {result_threatfox['inserted']} IOCs")
            except Exception as e:
                print(f"[❌] Lỗi ThreatFox: {e}")

            # 2️⃣ AbuseIPDB
            try:
                file_path = abuseipdb_service.save_ips_to_file()
                print(f"[✓] AbuseIPDB blacklist saved to {file_path}")
            except Exception as e:
                print(f"[❌] Lỗi AbuseIPDB: {e}")

            print("[✅] Hoàn tất cập nhật dữ liệu ThreatFox & AbuseIPDB.")
        except Exception as e:
            print(f"[!!!] Lỗi không mong đợi trong background updater: {e}")

        # Ngủ 2 ngày
        time.sleep(INTERVAL)



if __name__ == "__main__":
    updater_thread = threading.Thread(target=background_data_updater, daemon=True)
    updater_thread.start()
    print("[🚀] Flask app & background updater đã khởi động!")
    app.run(host="0.0.0.0", port=5000)
