# app.py

from flask import Flask
from flask_cors import CORS
from routes.frontend_api import frontend_api
from routes.operator_api import operator_api
from threading import Thread
from scheduler.updater import background_data_updater
app = Flask(__name__)
CORS(app)

# Register Blueprints
app.register_blueprint(frontend_api)
app.register_blueprint(operator_api)

if __name__ == "__main__":
    Thread(target=background_data_updater, daemon=True).start()
    print("[Scheduler] Background updater started")
    app.run(host="0.0.0.0", port=5000)
