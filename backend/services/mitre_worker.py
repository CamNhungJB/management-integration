# services/mitre_worker.py

import time
from datetime import datetime
from elasticsearch import Elasticsearch

import config
from AI_MITRE.Catboost.preprocessing.normalize_elastic import normalize_elastic_log
from AI_MITRE.Catboost.inference.engine import MitreEngine
from services.mitre_storage import save_mitre_result


# =========================
# CONFIG
# =========================
ELASTIC_URL = "http://localhost:9200"
ELASTIC_INDEX = "snort-alert-*"
BATCH_SIZE = 200
POLL_INTERVAL = 10  # seconds


# =========================
# INIT
# =========================
es = Elasticsearch(ELASTIC_URL)
engine = MitreEngine()


# =========================
# METADATA EXTRACTOR (QUAN TRỌNG)
# =========================
def extract_metadata(hit: dict) -> dict:
    src = hit.get("_source", {})
    snort = src.get("snort", {})

    def split_ip_port(value):
        if value and ":" in value:
            ip, port = value.rsplit(":", 1)
            try:
                return ip, int(port)
            except Exception:
                return ip, None
        return None, None

    src_ip, src_port = split_ip_port(snort.get("src_ap"))
    dst_ip, dst_port = split_ip_port(snort.get("dst_ap"))

    return {
        "timestamp": src.get("@timestamp"),

        # sensor
        "sensor_id": src.get("source") or src.get("agent", {}).get("id"),

        # network
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "proto": snort.get("proto"),

        # 🔥 THÊM MESSAGE (QUAN TRỌNG)
        "msg": snort.get("msg"),

        # (tuỳ chọn – để debug sau)
        "rule": snort.get("rule"),
        "action": snort.get("action"),
        "class": snort.get("class"),
    }


# =========================
# FETCH LOGS FROM ELASTIC
# =========================
def fetch_logs(last_ts=None):
    query = {
        "size": BATCH_SIZE,
        "sort": [{"@timestamp": "asc"}],
        "query": {
            "bool": {
                "filter": []
            }
        }
    }

    if last_ts:
        query["query"]["bool"]["filter"].append(
            {"range": {"@timestamp": {"gt": last_ts}}}
        )

    resp = es.search(index=ELASTIC_INDEX, body=query)
    return resp["hits"]["hits"]


# =========================
# MAIN LOOP
# =========================
def run_forever():
    print("[MITRE] Worker started")
    last_ts = None

    while True:
        try:
            hits = fetch_logs(last_ts)

            if not hits:
                time.sleep(POLL_INTERVAL)
                continue

            print(f"[MITRE] Got {len(hits)} logs")

            for hit in hits:
                src = hit.get("_source", {})
                last_ts = src.get("@timestamp")

                # 1️⃣ extract metadata (CHO MONGO)
                meta = extract_metadata(hit)


                # 2️⃣ normalize (CHO AI)
                features = normalize_elastic_log(hit)

                # 3️⃣ MITRE mapping
                mitre_result = engine.process_log(features)

                if mitre_result:
                    save_mitre_result(meta, mitre_result)

            time.sleep(POLL_INTERVAL)

        except Exception as e:
            print("[MITRE][ERROR]", e)
            time.sleep(POLL_INTERVAL)


# =========================
# ENTRYPOINT FOR APP.PY
# =========================
def start_worker():
    run_forever()
