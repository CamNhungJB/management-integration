import requests, time, json
from datetime import datetime
import config
from services.db_service import ensure_sqlite, save_to_mongo, save_to_sqlite
from utils.helpers import normalize_type

SUPPORTED_TYPES = {"ip", "domain", "url", "hash"}


def fetch_threatfox():
    """Lấy dữ liệu IOC từ ThreatFox API"""
    headers = {"Content-Type": "application/json", "Auth-Key": config.THREATFOX_AUTH_KEY}
    payload = {"query": "get_iocs", "days": config.THREATFOX_DAYS}
    r = requests.post(config.THREATFOX_API, headers=headers, json=payload, timeout=60)
    r.raise_for_status()
    j = r.json()
    if j.get("query_status") != "ok":
        raise RuntimeError(f"ThreatFox query failed: {j.get('query_status')} {j.get('message')}")
    return j.get("data", [])


def process_threatfox():
    """
    Lấy IOC từ ThreatFox, lưu vào MongoDB và SQLite.
    Trả về số lượng IOC đã lưu.
    """
    conn = ensure_sqlite()
    total_inserted = 0

    data = fetch_threatfox()
    for entry in data:
        try:
            ioc, raw_type = entry.get("ioc"), entry.get("ioc_type")
            if not ioc or not raw_type:
                continue

            itype = normalize_type(raw_type)
            if itype not in SUPPORTED_TYPES:
                continue

            conf = int(entry.get("confidence_level") or 0)
            if conf < config.THREATFOX_MIN_CONFIDENCE:
                continue

            meta = {
                "source": "threatfox",
                "threat_type": entry.get("threat_type"),
                "malware": entry.get("malware")
            }

            # Lưu vào SQLite (json.dumps an toàn với default=str)
            sid = save_to_sqlite({
                "ioc": ioc,
                "ioc_type": itype,
                "confidence": conf,
                "first_seen": entry.get("first_seen"),
                "last_seen": entry.get("last_seen"),
                "meta": meta,
                "source": "ThreatFox"
            }, conn)


            # Lưu vào MongoDB
            save_to_mongo({
                "ioc": ioc,
                "ioc_type": itype,
                "confidence": conf,
                "first_seen": entry.get("first_seen"),
                "last_seen": entry.get("last_seen"),
                "meta": meta,
                "sid": sid
            })


            total_inserted += 1
        except Exception as e:
            print(f"[!] Error processing IOC {entry.get('ioc')}: {e}")

    conn.close()
    return {"inserted": total_inserted}
