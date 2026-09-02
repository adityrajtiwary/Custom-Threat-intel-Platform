import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()

conn = psycopg2.connect(
    host=os.getenv("DB_HOST"), port=os.getenv("DB_PORT"),
    dbname=os.getenv("DB_NAME"), user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
)
cur = conn.cursor()

# suspicious ports -- ye khule ho to red flag
SUSPICIOUS_PORTS = {"4444", "3389", "445", "1080", "5985", "5986", "23", "3306", "6379"}

# saari IOCs + unka enrichment lo
cur.execute("""
    SELECT i.id, i.ioc_type, i.threat_type, i.times_seen, i.confidence,
           e.abuse_score, e.shodan_ports
    FROM iocs i
    LEFT JOIN ioc_enrichment e ON e.ioc_id = i.id
""")
rows = cur.fetchall()
print(f"Scoring {len(rows)} IOCs...")

updated = 0
for iid, itype, ttype, times_seen, conf, abuse, ports in rows:
    score = 0

    # 1. Threat feed me hai -> baseline malicious (30)
    #    (ye IOC feed se aaya, matlab already suspect)
    score += 30

    # 2. AbuseIPDB score (weight 0.4) -- max +40
    if abuse:
        score += int(abuse * 0.4)

    # 3. Shodan suspicious ports -- +20 agar koi red-flag port khula
    if ports and ports not in ("none", None):
        open_ports = set(ports.split(","))
        if open_ports & SUSPICIOUS_PORTS:
            score += 20

    # 4. Recurring (multiple baar/source dikhi) -> +15
    if times_seen and times_seen > 1:
        score += 15

    # 5. Source confidence (weight 0.15) -- max ~15
    if conf:
        score += int(conf * 0.15)

    # clamp 0-100
    score = max(0, min(100, score))

    # level
    if score >= 70:
        level = "HIGH"
    elif score >= 45:
        level = "MEDIUM"
    else:
        level = "LOW"

    cur.execute("UPDATE iocs SET risk_score=%s, risk_level=%s WHERE id=%s", (score, level, iid))
    updated += 1

conn.commit()

# summary
cur.execute("SELECT risk_level, COUNT(*) FROM iocs GROUP BY risk_level ORDER BY COUNT(*) DESC")
print(f"\nScored {updated} IOCs. Breakdown:")
for lvl, cnt in cur.fetchall():
    print(f"  {lvl}: {cnt}")

cur.close(); conn.close()
