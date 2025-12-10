# routes/frontend_api.py

from flask import Blueprint, jsonify, request
from datetime import datetime, timezone
from services import db_service
from bson import ObjectId
import config

frontend_api = Blueprint("frontend_api", __name__)


# 1. Lấy active rules (bundle)
@frontend_api.route('/api/v1/rules/active_bundle', methods=['GET'])
def get_active_rule_bundle():
    try:
        deploy_col = db_service.get_deployment_status_collection()
        deployment = deploy_col.find_one({"_id": config.DEPLOYMENT_ID})

        if not deployment or "active_rule_set_id" not in deployment:
            return jsonify({"error": "Active rule set not found"}), 404

        active_id = deployment["active_rule_set_id"]
        rules_col = db_service.get_rules_collection()

        query_id = ObjectId(active_id) if isinstance(active_id, str) and len(active_id) == 24 else active_id
        rules = list(rules_col.find({"rule_set_id": query_id}))

        contents = [r.get("content", "") for r in rules]

        return jsonify({
            "active_rule_set_id": str(active_id),
            "bundle": "\n".join(contents)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500



# 2. Lấy trạng thái deployment
@frontend_api.route('/api/v1/deployment/status', methods=['GET'])
def get_deployment_status():
    try:
        col = db_service.get_deployment_status_collection()
        doc = col.find_one({"_id": config.DEPLOYMENT_ID})

        return jsonify({
            "active_rule_set_id": str(doc["active_rule_set_id"]) if doc else None
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500



# 3. Sensor heartbeat
@frontend_api.route("/api/v1/sensors/heartbeat", methods=["POST"])
def sensor_heartbeat():
    try:
        data = request.get_json(force=True)
        required = ["sensor_id", "hostname", "ip_address", "current_rule_set_id"]

        if not all(k in data for k in required):
            return jsonify({"error": "Missing required fields"}), 400

        col = db_service.get_sensors_collection()

        col.update_one(
            {"_id": data["sensor_id"]},
            {
                "$set": {
                    "hostname": data["hostname"],
                    "ip_address": data["ip_address"],
                    "current_rule_set_id": data["current_rule_set_id"],
                    "last_seen": datetime.utcnow()
                }
            },
            upsert=True
        )

        return jsonify({"message": "Heartbeat updated"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500



# 4. Lấy danh sách sensors
@frontend_api.route("/api/v1/sensors", methods=["GET"])
def list_sensors():
    try:
        sensors_col = db_service.get_sensors_collection()
        rule_sets_col = db_service.get_rule_sets_collection()

        sensors = list(sensors_col.find({}))
        rule_sets = {str(rs["_id"]): rs for rs in rule_sets_col.find({})}

        now = datetime.now(timezone.utc)
        result = []

        for s in sensors:
            last_seen = s.get("last_seen")
            if isinstance(last_seen, datetime) and last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)

            diff = (now - last_seen).total_seconds() if isinstance(last_seen, datetime) else 999999
            status = "online" if diff < 600 else "offline"

            rule_info = rule_sets.get(str(s.get("current_rule_set_id")), {})
            rule_version = rule_info.get("version", "unknown")

            result.append({
                "sensor_id": s["_id"],
                "hostname": s.get("hostname"),
                "ip_address": s.get("ip_address"),
                "rule_version": rule_version,
                "current_rule_set_id": str(s.get("current_rule_set_id")),
                "status": status,
                "last_seen": last_seen.isoformat() if isinstance(last_seen, datetime) else None
            })

        return jsonify({"sensors": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500



# 5. Lịch sử Rule Sets
@frontend_api.route('/api/v1/rulesets', methods=['GET'])
def get_rulesets_history():
    try:
        rule_sets = db_service.get_all_rule_sets()
        return jsonify(db_service.mongo_to_json(rule_sets))
    except Exception as e:
        return jsonify({"error": str(e)}), 500



# 6. Lấy toàn bộ rule (nếu cần)
@frontend_api.route("/rules", methods=["GET"])
def get_rules():
    try:
        rules_col = db_service.get_rules_collection()
        rule_sets_col = db_service.get_rule_sets_collection()

        # Lấy tất cả rule
        rules = list(rules_col.find({}))

        # Map rule_set_id -> version
        rule_sets = {
            rs["_id"]: rs.get("version")
            for rs in rule_sets_col.find({}, {"version": 1})
        }

        # Gắn version vào từng rule
        for r in rules:
            rsid = r.get("rule_set_id")
            r["version"] = rule_sets.get(rsid)

        # Convert ObjectId, datetime -> string
        safe_rules = db_service.mongo_to_json(rules)

        return jsonify({"data": safe_rules}), 200

    except Exception as e:
        print("ERROR /rules:", e)
        return jsonify({"error": str(e)}), 500
@frontend_api.route("/api/ioc/search", methods=["GET"])
def search_ioc():
    try:
        query = request.args.get("q", "").strip()

        if not query:
            return jsonify({"error": "Missing query"}), 400

        # 1. Kiểm tra nếu input là IP → gọi AbuseIPDB API real-time
        import re
        ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
        
        if re.match(ip_pattern, query):
            # Gọi API AbuseIPDB real-time
            from services.abuseipdb_service import ABUSEIPDB_API_KEY
            import requests

            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
            params = {"ipAddress": query, "maxAgeInDays": "180"}

            r = requests.get(url, headers=headers, params=params)
            data = r.json()

            return jsonify({
                "source": "abuseipdb",
                "ioc": query,
                "data": data.get("data", {})
            })

        # 2. Nếu không phải IP → search IOC ThreatFox trong MongoDB
        col = db_service.get_mongo_IOC_collection()
        result = col.find_one({"ioc": query})

        if not result:
            return jsonify({"found": False, "ioc": query})

        result["_id"] = str(result["_id"])

        return jsonify({
            "found": True,
            "source": result.get("source"),
            "ioc": query,
            "data": result
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
