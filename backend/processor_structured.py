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

def normalize(ioc_type, value):
    if not value:
        return ioc_type, value
    v = value.strip()
    v = v.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    v = v.replace("hxxp://", "http://").replace("hxxps://", "https://")
    t = ioc_type.lower().strip()
    if t in ("ip", "ip:port", "ipv4"):
        t = "ip"; v = v.split(":")[0].strip()
    elif t == "domain":
        v = v.lower()
    elif t == "url":
        v = v.lower()
    elif t in ("md5","sha1","sha256","sha-1","sha-256",
               "md5_hash","sha1_hash","sha256_hash"):
        v = v.lower(); t = t.replace("_hash","").replace("-","")
    return t, v


def upsert_ioc(ioc_type, value, source, raw_item_id,
               malware=None, threat_type=None, reason=None, confidence=50):
    itype, val = normalize(ioc_type, value)
    if not val:
        return
    # IOC upsert (dedup on type+value)
    cur.execute("""
        INSERT INTO iocs (ioc_type, value, malware, threat_type, reason, confidence)
        VALUES (%s,%s,%s,%s,%s,%s)
        ON CONFLICT (ioc_type, value) DO UPDATE SET
            malware    = COALESCE(iocs.malware, EXCLUDED.malware),
            threat_type= COALESCE(iocs.threat_type, EXCLUDED.threat_type),
            reason     = COALESCE(iocs.reason, EXCLUDED.reason)
        RETURNING id
    """, (itype, val, malware, threat_type, reason, confidence))
    ioc_id = cur.fetchone()[0]

    # Sighting sirf tab jab is source se AAJ pehle na dikhi ho
    cur.execute("""
        SELECT 1 FROM ioc_sightings
        WHERE ioc_id=%s AND source=%s AND seen_at::date = now()::date LIMIT 1
    """, (ioc_id, source))
    if cur.fetchone() is None:
        cur.execute("""INSERT INTO ioc_sightings (ioc_id, source, raw_item_id)
                       VALUES (%s,%s,%s)""", (ioc_id, source, raw_item_id))
        # times_seen aur last_seen ko sightings ke hisaab se update karo
        cur.execute("""
            UPDATE iocs SET
                times_seen = (SELECT COUNT(*) FROM ioc_sightings WHERE ioc_id=%s),
                last_seen  = now(),
                is_active  = true
            WHERE id=%s
        """, (ioc_id, ioc_id))


def process_threatfox():
    cur.execute("""SELECT id,data FROM raw_items
                   WHERE source='threatfox' AND kind='ioc' AND processed=false""")
    rows = cur.fetchall(); print(f"ThreatFox: {len(rows)} to process")
    for rid, d in rows:
        upsert_ioc(d.get("ioc_type","unknown"), d.get("ioc",""),
                   "threatfox", rid,
                   malware=d.get("malware_printable") or d.get("malware"),
                   threat_type=d.get("threat_type"),
                   reason=d.get("threat_type_desc") or d.get("ioc_type_desc"),
                   confidence=d.get("confidence_level",50))
        cur.execute("UPDATE raw_items SET processed=true WHERE id=%s",(rid,))
    conn.commit()


def process_ransomware():
    cur.execute("""SELECT id,data FROM raw_items
                   WHERE source='ransomware.live' AND kind='ioc' AND processed=false""")
    rows = cur.fetchall(); print(f"ransomware.live: {len(rows)} to process")
    for rid, d in rows:
        g = d.get("group","unknown")
        upsert_ioc(d.get("ioc_type","unknown"), d.get("value",""),
                   "ransomware.live", rid, malware=g, threat_type="ransomware",
                   reason=f"Associated with {g} ransomware group", confidence=75)
        cur.execute("UPDATE raw_items SET processed=true WHERE id=%s",(rid,))
    conn.commit()


def process_cisa_kev():
    cur.execute("""SELECT id,data FROM raw_items
                   WHERE source='cisa_kev' AND kind='cve' AND processed=false""")
    rows = cur.fetchall(); print(f"CISA KEV: {len(rows)} to process")
    for rid, d in rows:
        cid = d.get("cveID")
        if not cid: continue
        cur.execute("""INSERT INTO cves (cve_id, description, kev_listed)
                       VALUES (%s,%s,true)
                       ON CONFLICT (cve_id) DO UPDATE SET kev_listed=true, last_seen=now()""",
                    (cid, d.get("shortDescription") or d.get("vulnerabilityName")))
        cur.execute("UPDATE raw_items SET processed=true WHERE id=%s",(rid,))
    conn.commit()


process_threatfox()
process_ransomware()
process_cisa_kev()

cur.execute("SELECT COUNT(*) FROM iocs");          print(f"\nUnique IOCs: {cur.fetchone()[0]}")
cur.execute("SELECT COUNT(*) FROM ioc_sightings"); print(f"Total sightings: {cur.fetchone()[0]}")
cur.execute("SELECT COUNT(*) FROM iocs WHERE times_seen>1"); print(f"Recurring IOCs: {cur.fetchone()[0]}")
cur.execute("SELECT COUNT(*) FROM cves");          print(f"CVEs: {cur.fetchone()[0]}")
cur.close(); conn.close()
