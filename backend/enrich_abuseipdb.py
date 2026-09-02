import os
import time
import requests
import psycopg2
from dotenv import load_dotenv

load_dotenv()

KEY = os.getenv("ABUSEIPDB_KEY")
URL = "https://api.abuseipdb.com/api/v2/check"
HEADERS = {"Key": KEY, "Accept": "application/json"}

# ek run me kitne IPs (rate limit safe -- free tier 1000/day)
BATCH = int(os.getenv("ENRICH_BATCH", "50"))

conn = psycopg2.connect(
    host=os.getenv("DB_HOST"), port=os.getenv("DB_PORT"),
    dbname=os.getenv("DB_NAME"), user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
)
cur = conn.cursor()

# active IPs jo abhi tak enrich nahi hui (recurring/active pehle)
cur.execute("""
    SELECT i.id, i.value FROM iocs i
    LEFT JOIN ioc_enrichment e ON e.ioc_id = i.id
    WHERE i.ioc_type='ip' AND i.is_active=true AND e.ioc_id IS NULL
    ORDER BY i.times_seen DESC, i.last_seen DESC
    LIMIT %s
""", (BATCH,))
targets = cur.fetchall()
print(f"Enriching {len(targets)} IPs via AbuseIPDB...")

done = 0
for ioc_id, ip in targets:
    try:
        r = requests.get(URL, headers=HEADERS,
                         params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=20)
        if r.status_code == 429:
            print("  Rate limit hit -- rukte hain, baad me continue")
            break
        if r.status_code != 200:
            print(f"  {ip}: HTTP {r.status_code}, skip")
            time.sleep(1)
            continue
        d = r.json().get("data", {})
        cur.execute("""
            INSERT INTO ioc_enrichment (ioc_id, abuse_score, abuse_reports, abuse_country, abuse_isp, abuse_usage)
            VALUES (%s,%s,%s,%s,%s,%s)
            ON CONFLICT (ioc_id) DO UPDATE SET
                abuse_score=EXCLUDED.abuse_score, abuse_reports=EXCLUDED.abuse_reports,
                abuse_country=EXCLUDED.abuse_country, abuse_isp=EXCLUDED.abuse_isp,
                abuse_usage=EXCLUDED.abuse_usage, enriched_at=now()
        """, (ioc_id, d.get("abuseConfidenceScore"), d.get("totalReports"),
              d.get("countryCode"), d.get("isp"), d.get("usageType")))
        conn.commit()
        done += 1
        print(f"  {ip}: abuse={d.get('abuseConfidenceScore')}% reports={d.get('totalReports')} ({d.get('countryCode')})")
    except Exception as e:
        print(f"  {ip}: ERROR {e}")
    time.sleep(1.5)  # rate limit safe

print(f"\nDone. Enriched: {done}")
cur.close(); conn.close()
