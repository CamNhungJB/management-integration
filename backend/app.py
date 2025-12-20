# app.py
import threading
from flask import Flask
from flask_cors import CORS
from routes.frontend_api import frontend_api
from routes.operator_api import operator_api
from routes.mitre_api import mitre_bp
from threading import Thread
from scheduler.updater import background_data_updater
from services.mitre_worker import start_worker
app = Flask(__name__)
CORS(app)

# Register Blueprints
app.register_blueprint(frontend_api)
app.register_blueprint(operator_api)
app.register_blueprint(mitre_bp)
def start_background_services():
    t = threading.Thread(
        target=start_worker,
        daemon=True   # rất quan trọng
    )
    t.start()
    print("[APP] MITRE worker started in background")

if __name__ == "__main__":
    start_background_services()
    Thread(target=background_data_updater, daemon=True).start()
    print("[Scheduler] Background updater started")
    app.run(host="0.0.0.0", port=5000)
