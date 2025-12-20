# services/mitre_storage.py

from datetime import datetime
from pymongo import MongoClient
import config

client = MongoClient(config.MONGO_URI)
db = client[config.MONGO_DB]
mitre_col = db[config.MONGO_COL_MITRE]


def save_mitre_result(meta: dict, mitre_result: dict):
    doc = {
        # ===== Time =====
        "timestamp": meta.get("timestamp"),
        "created_at": datetime.utcnow(),

        # ===== Sensor / Network =====
        "sensor_id": meta.get("sensor_id"),
        "src_ip": meta.get("src_ip"),
        "dst_ip": meta.get("dst_ip"),
        "src_port": meta.get("src_port"),
        "dst_port": meta.get("dst_port"),
        "proto": meta.get("proto"),

        # 🔥 MESSAGE CHO BẢNG LOG CHI TIẾT
        "msg": meta.get("msg"),

        # ===== MITRE =====
        "tactic": mitre_result.get("tactic"),
        "technique": mitre_result.get("technique"),
        "confidence": mitre_result.get("confidence"),
        "tactic_confidence": mitre_result.get("tactic_confidence"),
        "technique_confidence": mitre_result.get("technique_confidence"),
    }

    mitre_col.insert_one(doc)
