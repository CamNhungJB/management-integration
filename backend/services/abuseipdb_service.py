# backend/services/abuseipdb_service.py
import os
import requests
from datetime import datetime
from dotenv import load_dotenv
import config
import tempfile
import json
# Load biến môi trường (chứa API key)
load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/blacklist"


def fetch_abuseipdb(limit=None, confidence=None):
    """
    Fetch danh sách IP đen từ AbuseIPDB.
    Trả về list các dict: [{ip, confidence, last_reported_at}, ...]
    """
    limit = limit or config.ABUSEIPDB_LIMIT
    confidence = confidence or config.ABUSEIPDB_CONFIDENCE

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "limit": str(limit),
        "confidenceMinimum": str(confidence)
    }

    r = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=60)
    r.raise_for_status()
    j = r.json()

    data = j.get("data", [])
    results = []

    for entry in data:
        ip = entry.get("ipAddress")
        conf = int(entry.get("abuseConfidenceScore", 0))
        last_reported = entry.get("lastReportedAt")
        if ip and conf >= confidence:
            results.append({
                "ip": ip,
                "confidence": conf,
                "last_reported_at": last_reported
            })

    return results


def process_abuseipdb(limit=None, confidence=None):
    """
    Fetch dữ liệu nhưng không lưu DB, chỉ trả về danh sách IP.
    """
    limit = limit or config.ABUSEIPDB_LIMIT
    confidence = confidence or config.ABUSEIPDB_CONFIDENCE
    data = fetch_abuseipdb(limit=limit, confidence=confidence)
    now = datetime.utcnow().isoformat() + "Z"

    print(f"[{now}] Fetched {len(data)} IPs from AbuseIPDB (confidence >= {confidence})")
    return {"count": len(data), "ips": [d["ip"] for d in data]}


def save_ips_to_file(filename="data/abuseipdb_blacklist.txt", limit=None, confidence=None):
    """
    Fetch IP từ AbuseIPDB và lưu vào file blacklist.
    - Lọc trùng IP
    - Ghi file an toàn (atomic)
    """
    result = process_abuseipdb(limit=limit, confidence=confidence)
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    unique_ips = sorted(set(result["ips"]))

    tmp = tempfile.NamedTemporaryFile("w", delete=False)
    for ip in unique_ips:
        tmp.write(ip + "\n")
    tmp.flush()
    os.replace(tmp.name, filename)

    print(f"[+] Saved {len(unique_ips)} unique IPs to {filename}")
    return filename
