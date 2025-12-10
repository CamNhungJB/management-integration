# routes/operator_api.py

from flask import Blueprint, jsonify, request
from services.rule_generator import publish_rules_to_mongo
from services import threatfox_service, abuseipdb_service, db_service
from bson import ObjectId
import config

operator_api = Blueprint("operator_api", __name__)


# 1. Publish Rule Set mới
@operator_api.route('/api/admin/rules/publish', methods=['POST'])
def publish_new_rules():
    try:
        result = publish_rules_to_mongo()

        if isinstance(result, dict):
            return jsonify({
                "status": "success",
                "version": result["version"],
                "rule_set_id": result["rule_set_id"],
                "total_rules": result["total_rules"]
            }), 201
        else:
            return jsonify({"status": "failed"}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500



# 2. Fetch ThreatFox
@operator_api.route('/api/admin/fetch/threatfox', methods=['POST'])
def fetch_threatfox():
    try:
        result = threatfox_service.process_threatfox()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500



# 3. Fetch AbuseIPDB
@operator_api.route('/api/admin/fetch/abuseipdb', methods=['POST'])
def fetch_abuseipdb():
    try:
        path = abuseipdb_service.save_ips_to_file()
        return jsonify({"status": "saved", "file": path})
    except Exception as e:
        return jsonify({"error": str(e)}), 500



# 4. Rollback / Activate rule set
@operator_api.route('/api/admin/deployment/activate', methods=['POST'])
def activate_rule_set():
    try:
        rid = request.json.get("rule_set_id")
        if not rid:
            return jsonify({"error": "Missing rule_set_id"}), 400

        rule_set_id = ObjectId(rid)

        if not db_service.get_rule_set_by_id(rule_set_id):
            return jsonify({"error": "Rule set not found"}), 404

        db_service.set_active_rule_set(rule_set_id)

        return jsonify({"status": "activated", "rule_set_id": rid})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
