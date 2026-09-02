import os
import time
import requests
import psycopg2
from dotenv import load_dotenv

load_dotenv()

KEY = os.getenv("SHODAN_KEY")
BATCH = int(os.getenv("SHODAN_BATCH", "30"))

conn = psycopg2.connect(
    host=os.getenv("DB_HOST"), port=os.getenv("DB_PORT"),
    dbname=os.getenv("DB_NAME"), user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
)
cur = conn.cursor()

# active IPs jinka shodan data abhi nahi (enrichment row hai par shodan null)
cur.execute("""
    SELECT i.id, i.value FROM iocs i
    JOIN ioc_enrichment e ON e.ioc_id = i.id
    WHERE i.ioc_type='ip' AND i.is_active=true AND e.shodan_ports IS NULL
    ORDER BY i.times_seen DESC LIMIT %s
""", (BATCH,))
targets = cur.fetchall()
print(f"Shodan enriching {len(targets)} IPs...")

done = 0
for ioc_id, ip in targets:
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}",
                         params={"key": KEY}, timeout=20)
        if r.status_code == 404:
            # Shodan ke paas is IP ka data nahi -- mark empty taaki dobara na try kare
            cur.execute("UPDATE ioc_enrichment SET shodan_ports='none', enriched_at=now() WHERE ioc_id=%s", (ioc_id,))
            conn.commit()
            print(f"  {ip}: no shodan data")
            time.sleep(1)
            continue
        if r.status_code == 429:
            print("  Rate limit -- rukte hain")
            break
        if r.status_code != 200:
            print(f"  {ip}: HTTP {r.status_code}")
            time.sleep(1)
            continue
        d = r.json()
        ports = ",".join(str(p) for p in d.get("ports", []))
        org = d.get("org", "")
        cur.execute("""UPDATE ioc_enrichment SET shodan_ports=%s, shodan_org=%s, enriched_at=now()
                       WHERE ioc_id=%s""", (ports or 'none', org, ioc_id))
        conn.commit()
        done += 1
        print(f"  {ip}: ports=[{ports}] org={org}")
    except Exception as e:
        print(f"  {ip}: ERROR {e}")
    time.sleep(1.5)

print(f"\nDone. Shodan enriched: {done}")
cur.close(); conn.close()
