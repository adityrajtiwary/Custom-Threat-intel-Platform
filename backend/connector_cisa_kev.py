import os
import json
import hashlib
import requests
import psycopg2
from dotenv import load_dotenv

load_dotenv()

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

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
        ("cisa_kev", kind, json.dumps(payload), h),
    )
    return cur.rowcount == 1

print("Fetching CISA KEV catalog...")
resp = requests.get(KEV_URL, timeout=60)
resp.raise_for_status()
catalog = resp.json()

vulns = catalog.get("vulnerabilities", [])
print(f"Got {len(vulns)} known-exploited CVEs")

inserted = 0
for v in vulns:
    if insert_raw("cve", v):
        inserted += 1

conn.commit()
print(f"Inserted: {inserted} | Skipped (duplicates): {len(vulns) - inserted}")
cur.close()
conn.close()
