# routes/mitre_routes.py

from flask import Blueprint, request, jsonify
from pymongo import MongoClient
from datetime import datetime, timedelta
import config

mitre_bp = Blueprint("mitre", __name__)

# MongoDB connection
client = MongoClient(config.MONGO_URI)
db = client[config.MONGO_DB]
mitre_col = db[config.MONGO_COL_MITRE]


@mitre_bp.route("/api/v1/mitre/results", methods=["GET"])
def get_mitre_results():
    """
    API cho frontend dashboard:
    - Lấy kết quả MITRE đã xử lý
    - Hỗ trợ incremental fetch qua tham số `after`
    """

    # -------- Query params (safe parse) --------
    limit_raw = request.args.get("limit")
    limit = int(limit_raw) if limit_raw and limit_raw.isdigit() else 50

    skip_raw = request.args.get("skip")
    skip = int(skip_raw) if skip_raw and skip_raw.isdigit() else 0

    sensor_id = request.args.get("sensor_id")
    tactic = request.args.get("tactic")

    # incremental param
    after = request.args.get("after")

    # -------- Build filter --------
    query = {}

    if sensor_id:
        query["sensor_id"] = sensor_id

    if tactic:
        query["tactic"] = tactic

    # 🔑 incremental: chỉ lấy log mới hơn mốc thời gian đã nhận
    if after:
        query["created_at"] = {"$gt": after}

    # -------- Query MongoDB --------
    cursor = (
        mitre_col
        .find(query)
        .sort("created_at", -1)      # mới nhất trước
        .skip(skip)
        .limit(limit)
    )

    results = list(cursor)

    # -------- Serialize ObjectId --------
    for r in results:
        r["_id"] = str(r["_id"])

    return jsonify({
        "count": len(results),
        "data": results
    })

@mitre_bp.route("/api/v1/mitre/summary", methods=["GET"])
def get_mitre_summary():
    """
    Summary API:
    - Tổng hợp MITRE logs theo ngày (mặc định: hôm nay)
    - Có thể filter theo sensor_id
    - Sort theo count DESC
    - Giới hạn top technique
    - Trả metadata generated_at
    """

    # ===== Query params =====
    date_str = request.args.get("date")          # YYYY-MM-DD
    sensor_id = request.args.get("sensor_id")
    top_n = request.args.get("top_n", "5")       # top technique
    top_n = int(top_n) if top_n.isdigit() else 5

    # ===== Xác định khoảng thời gian =====
    if date_str:
        try:
            start = datetime.strptime(date_str, "%Y-%m-%d")
        except ValueError:
            return jsonify({"error": "Invalid date format, use YYYY-MM-DD"}), 400
    else:
        start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    end = start + timedelta(days=1)

    # ===== Build match filter =====
    match = {
        "created_at": {
            "$gte": start,
            "$lt": end
        }
    }

    if sensor_id:
        match["sensor_id"] = sensor_id

    # ===== Aggregation pipeline =====
    pipeline = [
        {"$match": match},
        {
            "$facet": {
                "total": [
                    {"$count": "count"}
                ],

                "by_sensor": [
                    {
                        "$group": {
                            "_id": "$sensor_id",
                            "count": {"$sum": 1}
                        }
                    }
                ],

                "by_tactic": [
                    {
                        "$group": {
                            "_id": "$tactic",
                            "count": {"$sum": 1}
                        }
                    }
                ],

                "by_technique": [
                    {
                        "$group": {
                            "_id": "$technique",
                            "count": {"$sum": 1}
                        }
                    }
                ]
            }
        }
    ]

    agg = list(mitre_col.aggregate(pipeline))[0]

    total_logs = agg["total"][0]["count"] if agg["total"] else 0

    # ===== Helper: thêm percent =====
    def with_percent(items):
        result = []
        for it in items:
            percent = round((it["count"] / total_logs) * 100, 2) if total_logs > 0 else 0
            result.append({
                "name": it["_id"],
                "count": it["count"],
                "percent": percent
            })
        return result

    # ===== Sort & limit =====
    by_sensor = sorted(
        with_percent(agg["by_sensor"]),
        key=lambda x: x["count"],
        reverse=True
    )

    by_tactic = sorted(
        with_percent(agg["by_tactic"]),
        key=lambda x: x["count"],
        reverse=True
    )

    by_technique = sorted(
        with_percent(agg["by_technique"]),
        key=lambda x: x["count"],
        reverse=True
    )[:top_n]

    # ===== Response =====
    return jsonify({
        "date": start.strftime("%Y-%m-%d"),
        "sensor_id": sensor_id or "ALL",
        "total_logs": total_logs,

        "by_sensor": by_sensor,
        "by_tactic": by_tactic,
        "by_technique": by_technique,

        "generated_at": datetime.utcnow().isoformat() + "Z"
    })
