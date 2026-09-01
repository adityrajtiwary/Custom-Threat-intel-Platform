import os
import json
import time
import hashlib
import requests
import psycopg2
from dotenv import load_dotenv

load_dotenv()

NVD_KEY = os.getenv("NVD_KEY")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS = {"apiKey": NVD_KEY}

# test ke liye kitne CVEs enrich karne hain (poora karne ke liye None)
LIMIT = None

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
        ("nvd", kind, json.dumps(payload), h),
    )
    return cur.rowcount == 1

# CISA KEV se CVE IDs uthao
cur.execute("""
    SELECT DISTINCT data->>'cveID'
    FROM raw_items
    WHERE source='cisa_kev' AND data->>'cveID' IS NOT NULL
    ORDER BY 1
""")
cve_ids = [r[0] for r in cur.fetchall()]
if LIMIT:
    cve_ids = cve_ids[:LIMIT]
print(f"Enriching {len(cve_ids)} CVEs from NVD...")

inserted = 0
for i, cve_id in enumerate(cve_ids, 1):
    try:
        r = requests.get(NVD_URL, headers=HEADERS,
                         params={"cveId": cve_id}, timeout=30)
        if r.status_code != 200:
            print(f"  [{i}/{len(cve_ids)}] {cve_id}: HTTP {r.status_code}")
            time.sleep(1)
            continue
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            print(f"  [{i}/{len(cve_ids)}] {cve_id}: not found in NVD")
            time.sleep(0.7)
            continue

        cve = vulns[0]["cve"]

        # CVSS score nikaalo (v3.1 pehle, phir v3.0, phir v2)
        cvss, severity = None, None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]["cvssData"]
                cvss = m.get("baseScore")
                severity = m.get("baseSeverity") or metrics[key][0].get("baseSeverity")
                break

        # description (English)
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        record = {
            "cve_id": cve.get("id"),
            "cvss_score": cvss,
            "severity": severity,
            "description": desc,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
        }
        if insert_raw("cve_detail", record):
            inserted += 1
        print(f"  [{i}/{len(cve_ids)}] {cve_id}: CVSS {cvss} ({severity})")
    except Exception as e:
        print(f"  [{i}/{len(cve_ids)}] {cve_id}: ERROR {e}")

    time.sleep(0.7)  # NVD rate limit (key ke saath)

conn.commit()
print(f"\nDone. New CVE details inserted: {inserted}")
cur.close()
conn.close()
