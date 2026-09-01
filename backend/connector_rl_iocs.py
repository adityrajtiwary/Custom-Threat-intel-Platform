import os
import json
import time
import hashlib
import requests
import psycopg2
from dotenv import load_dotenv

load_dotenv()

RL_BASE = os.getenv("RL_BASE")
RL_TOKEN = os.getenv("RL_TOKEN")
HEADERS = {"X-Api-Key": RL_TOKEN}

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
        ("ransomware.live", kind, json.dumps(payload), h),
    )
    return cur.rowcount == 1

# 1. saare groups ka index lo
print("Fetching group index...")
idx = requests.get(f"{RL_BASE}/iocs", headers=HEADERS, timeout=30).json()
groups = [g["group"] for g in idx.get("groups", [])]
print(f"Found {len(groups)} groups")

total_ioc_rows = 0
inserted = 0

# 2. har group ki actual IOCs pull karo
for i, group in enumerate(groups, 1):
    try:
        r = requests.get(f"{RL_BASE}/iocs/{group}", headers=HEADERS, timeout=30)
        if r.status_code != 200:
            print(f"  [{i}/{len(groups)}] {group}: HTTP {r.status_code}, skip")
            time.sleep(1)
            continue
        data = r.json()
        iocs = data.get("iocs", {})

        # har type (ip, md5, sha256, btc, mail...) ki har value ek raw row
        for ioc_type, values in iocs.items():
            for val in values:
                row = {"group": group, "ioc_type": ioc_type, "value": val}
                if insert_raw("ioc", row):
                    inserted += 1
                total_ioc_rows += 1

        types_summary = {k: len(v) for k, v in iocs.items()}
        print(f"  [{i}/{len(groups)}] {group}: {types_summary}")
    except Exception as e:
        print(f"  [{i}/{len(groups)}] {group}: ERROR {e}")

    time.sleep(1)  # rate limit se bachne ke liye

conn.commit()
print(f"\nDone. Total IOC values seen: {total_ioc_rows} | New inserted: {inserted}")
cur.close()
conn.close()
