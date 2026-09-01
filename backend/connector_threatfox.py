import os
import json
import hashlib
import requests
import psycopg2
from dotenv import load_dotenv

load_dotenv()

ABUSECH_KEY = os.getenv("ABUSECH_KEY")
API_URL = "https://threatfox-api.abuse.ch/api/v1/"
HEADERS = {"Auth-Key": ABUSECH_KEY}

conn = psycopg2.connect(
    host=os.getenv("DB_HOST"), port=os.getenv("DB_PORT"),
    dbname=os.getenv("DB_NAME"), user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
)
cur = conn.cursor()

def insert_raw(kind, payload):
    raw = json.dumps(payload, sort_keys=True)
    h = hashlib.sha256(raw.encode()).hexdigest()
    cur.execute(
        """INSERT INTO raw_items (source, kind, data, content_hash)
           VALUES (%s,%s,%s,%s) ON CONFLICT (content_hash) DO NOTHING""",
        ("threatfox", kind, json.dumps(payload), h),
    )
    return cur.rowcount == 1

# pichhle 3 din ki saari IOCs
print("Fetching ThreatFox IOCs (last 3 days)...")
resp = requests.post(API_URL, headers=HEADERS,
                     json={"query": "get_iocs", "days": 3}, timeout=60)
data = resp.json()

if data.get("query_status") != "ok":
    print(f"API error: {data.get('query_status')}")
    print(json.dumps(data, indent=2)[:500])
    raise SystemExit(1)

iocs = data.get("data", [])
print(f"Got {len(iocs)} IOCs from ThreatFox")

inserted = 0
for ioc in iocs:
    if insert_raw("ioc", ioc):
        inserted += 1

conn.commit()
print(f"Inserted: {inserted} | Skipped (duplicates): {len(iocs) - inserted}")

cur.close()
conn.close()
