import json
import os, sqlite3
from pymongo import MongoClient
from datetime import datetime
import config

def ensure_sqlite():
    os.makedirs(os.path.dirname(config.SQLITE_DB), exist_ok=True)
    conn = sqlite3.connect(config.SQLITE_DB)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS ioc (
      id INTEGER PRIMARY KEY,
      ioc TEXT NOT NULL,
      ioc_type TEXT NOT NULL,
      source TEXT,
      confidence INTEGER DEFAULT 0,
      first_seen TEXT,
      last_seen TEXT,
      sid INTEGER UNIQUE,
      meta TEXT,
      updated_at INTEGER,
      UNIQUE(ioc, ioc_type)
    );
    """)
    conn.commit()
    return conn
def save_to_sqlite(entry, conn):
    """
    Lưu IOC vào SQLite.
    entry: dict chứa các key: ioc, ioc_type, confidence, first_seen, last_seen, meta, source
    conn: sqlite3.Connection
    """
    cur = conn.cursor()

    # Lấy SID tự tăng (tránh trùng)
    cur.execute("SELECT MAX(sid) FROM ioc")
    row = cur.fetchone()
    max_sid = row[0] if row[0] is not None else 1000000
    sid = max_sid + 1

    cur.execute("""
        INSERT OR REPLACE INTO ioc (ioc, ioc_type, confidence, first_seen, last_seen, meta, sid, source, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, strftime('%s','now'))
    """, (
        entry["ioc"],
        entry["ioc_type"],
        entry.get("confidence", 0),
        entry.get("first_seen"),
        entry.get("last_seen"),
        json.dumps(entry.get("meta", {})),  # meta lưu dạng JSON string
        sid,
        entry.get("source", "ThreatFox")
    ))

    conn.commit()
    return sid
def get_mongo_IOC_collection():
    client = MongoClient(config.MONGO_URI)
    db = client[config.MONGO_DB]
    return db[config.MONGO_COL_IOC]
def get_mongo_db():
    """MỚI: Hàm helper để lấy DB object."""
    client = MongoClient(config.MONGO_URI)
    return client[config.MONGO_DB]

def get_rule_sets_collection():
    """MỚI: Lấy collection 'rule_sets'."""
    db = get_mongo_db()
    return db[config.MONGO_COL_RULE_SETS]

def get_rules_collection():
    """MỚI: Lấy collection 'rules'."""
    db = get_mongo_db()
    return db[config.MONGO_COL_RULES]

def get_deployment_status_collection():
    """MỚI: Lấy collection 'deployment_status'."""
    db = get_mongo_db()
    return db[config.MONGO_COL_DEPLOYMENT]

def get_sensors_collection():
    """Lấy collection 'sensors'."""
    db = get_mongo_db()
    return db["sensors"]
def create_new_rule_set(version_name, description, rule_count, sources):
    """
    MỚI: (Bước 1) Tạo một document metadata trong 'rule_sets'.
    Trả về _id của rule set vừa tạo.
    """
    col = get_rule_sets_collection()
    doc = {
        "version": version_name,
        "timestamp": datetime.utcnow(),
        "description": description,
        "rule_count": rule_count,
        "sources": sources
    }
    result = col.insert_one(doc)
    print(f"[DB] Đã tạo Rule Set '{version_name}' với ID: {result.inserted_id}")
    return result.inserted_id

def insert_rules_batch(rules_list, rule_set_id):
    """
    MỚI: (Bước 2) Chèn hàng loạt các rule vào 'rules'.
    rules_list: Là một danh sách các dictionary (mỗi dict là 1 rule).
    rule_set_id: ID trả về từ hàm create_new_rule_set.
    """
    col = get_rules_collection()
    if not rules_list:
        print("[DB] Không có rule nào để chèn.")
        return 0

    # Chuẩn bị các document để chèn hàng loạt
    documents_to_insert = []
    for rule_data in rules_list:
        documents_to_insert.append({
            "rule_set_id": rule_set_id, # Khóa ngoại trỏ về rule_sets
            "content": rule_data["content"],
            "source": rule_data["source"],
            "threat_id": rule_data.get("threat_id", "N/A")
        })

    result = col.insert_many(documents_to_insert)
    print(f"[DB] Đã chèn thành công {len(result.inserted_ids)} rules vào DB.")
    return len(result.inserted_ids)

def set_active_rule_set(rule_set_id):
    """
    MỚI: (Bước 3) Cập nhật 'deployment_status' để trỏ vào rule_set_id mới.
    Đây là "công tắc" kích hoạt phiên bản mới cho sensor.
    """
    col = get_deployment_status_collection()
    
    # Dùng _id cố định (từ config) để luôn update 1 document duy nhất
    result = col.update_one(
        {"_id": config.DEPLOYMENT_ID},
        {
            "$set": {
                "active_rule_set_id": rule_set_id,
                "last_updated": datetime.utcnow()
            }
        },
        upsert=True # Tự động tạo nếu chưa tồn tại
    )
    
    print(f"[DB] Đã kích hoạt Rule Set ID: {rule_set_id} cho '{config.DEPLOYMENT_ID}'")
    return result
    
def save_to_mongo(entry):
    col = get_mongo_IOC_collection()
    doc = {
        "ioc": entry["ioc"],
        "ioc_type": entry["ioc_type"],
        "source": "threatfox",
        "confidence": entry.get("confidence", 0),
        "first_seen": entry.get("first_seen"),
        "last_seen": entry.get("last_seen"),
        "meta": entry.get("meta"),
        "inserted_at": datetime.utcnow(),
    }
    # >>> Thêm sid nếu có <<<
    if "sid" in entry:
        doc["sid"] = entry["sid"]
    col.update_one(
        {"ioc": entry["ioc"], "ioc_type": entry["ioc_type"]},
        {"$set": doc},
        upsert=True
    )
def get_all_rule_sets():
    """
    Lấy toàn bộ rule set đã publish, sort theo timestamp giảm dần.
    """
    col = get_rule_sets_collection()
    return list(col.find({}).sort("timestamp", -1))


def mongo_to_json(data):
    """
    Convert document MongoDB (ObjectId, datetime) thành JSON serializable.
    """
    result = []
    for item in data:
        converted = {}
        for key, value in item.items():
            if key in ("_id", "rule_set_id"):   # <── FIX QUAN TRỌNG
                converted[key] = str(value)
            elif isinstance(value, datetime):
                converted[key] = value.isoformat()
            else:
                converted[key] = value
        result.append(converted)
    return result
