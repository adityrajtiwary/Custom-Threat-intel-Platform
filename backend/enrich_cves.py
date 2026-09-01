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

# NVD ka data raw_items (source=nvd, kind=cve_detail) se lo
cur.execute("""
    SELECT data FROM raw_items
    WHERE source='nvd' AND kind='cve_detail'
""")
rows = cur.fetchall()
print(f"NVD records to merge: {len(rows)}")

updated = 0
for (d,) in rows:
    cve_id = d.get("cve_id")
    if not cve_id:
        continue
    cur.execute("""
        UPDATE cves SET
            cvss_score  = %s,
            severity    = %s,
            description = COALESCE(%s, description),
            published   = COALESCE(published, %s::timestamptz)
        WHERE cve_id = %s
    """, (
        d.get("cvss_score"),
        d.get("severity"),
        d.get("description"),
        d.get("published"),
        cve_id,
    ))
    if cur.rowcount > 0:
        updated += 1

conn.commit()
print(f"Enriched {updated} CVEs with CVSS + severity")

# Summary
cur.execute("SELECT severity, COUNT(*) FROM cves WHERE severity IS NOT NULL GROUP BY severity ORDER BY COUNT(*) DESC")
print("\nSeverity breakdown:")
for sev, cnt in cur.fetchall():
    print(f"  {sev}: {cnt}")

cur.execute("SELECT COUNT(*) FROM cves WHERE kev_listed=true")
print(f"\nActively exploited (KEV): {cur.fetchone()[0]}")
cur.execute("SELECT COUNT(*) FROM cves WHERE cvss_score >= 9.0")
print(f"Critical (CVSS >= 9.0): {cur.fetchone()[0]}")

cur.close(); conn.close()
