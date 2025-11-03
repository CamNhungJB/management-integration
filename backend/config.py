import os
from dotenv import load_dotenv

# Load .env
load_dotenv()
MONGO_URI = "mongodb://localhost:27017"
MONGO_DB = "data"
MONGO_COL_IOC = "IOC"
MONGO_COL_RULE_SETS = "rule_sets"
MONGO_COL_RULES = "rules"
MONGO_COL_DEPLOYMENT = "deployment_status"
DEPLOYMENT_ID = "production_sensors"

SQLITE_DB = "/home/central/TI/ThreatFox/threat_iocs.db"
RULE_FILE = "/home/central/rules/snort/all_rule.rules"
THREATFOX_RULE_FILE = "/home/central/rules/snort/threatfox.rules"
ABUSEIPDB_RULE_FILE = "/home/central/rules/snort/abuseipdb.rules"

THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/blacklist"
THREATFOX_AUTH_KEY = os.getenv("THREATFOX_AUTH_KEY")
#abuseIPDB
ABUSEIPDB_LIMIT = 100     # số lượng IP tối đa khi fetch
ABUSEIPDB_CONFIDENCE = 90 # ngưỡng confidence
ABUSEIPDB_SID_start = 2000000
ABUSEIPDB_OUTPUT_FILE = "data/abuseipdb_blacklist.txt"
#threatfox
THREATFOX_DAYS = 5
THREATFOX_MIN_CONFIDENCE = 50
THREATFOX_SID_START = 1000000
THREATFOX_MAX_RULES = 20000
THREATFOX_VALIDATE_AND_RELOAD = False
