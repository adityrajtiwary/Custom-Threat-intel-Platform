import os
import re
import json
import ipaddress
import requests
import psycopg2
from dotenv import load_dotenv

load_dotenv()

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.2"

conn = psycopg2.connect(
    host=os.getenv("DB_HOST"), port=os.getenv("DB_PORT"),
    dbname=os.getenv("DB_NAME"), user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
)
cur = conn.cursor()

# --- Regex (structured IOCs pehle nikaalo) ---
RE_CVE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
RE_IP  = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
RE_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
RE_SHA1   = re.compile(r'\b[a-fA-F0-9]{40}\b')
RE_MD5    = re.compile(r'\b[a-fA-F0-9]{32}\b')

def valid_ip(s):
    try:
        ip = ipaddress.ip_address(s)
        return not (ip.is_private or ip.is_loopback or ip.is_reserved
                    or ip.is_multicast or ip.is_unspecified or ip.is_link_local)
    except ValueError:
        return False

def regex_iocs(text):
    ips = [ip for ip in set(RE_IP.findall(text)) if valid_ip(ip)]
    return {
        "cve": sorted(set(RE_CVE.findall(text))),
        "ip": sorted(ips),
        "sha256": sorted(set(RE_SHA256.findall(text))),
        "sha1": sorted(set(RE_SHA1.findall(text))),
        "md5": sorted(set(RE_MD5.findall(text))),
    }

PROMPT = """You are a cyber threat intelligence analyst. Read the article and extract structured intel.
Return ONLY valid JSON (no markdown) with this exact shape:
{{
  "apt_groups": [],
  "malware": [],
  "target_sectors": [],
  "summary": "2 line threat summary",
  "ioc_reasons": {{"indicator_value": "one line why malicious"}}
}}
Rules: use [] if nothing found (never "Unknown"). Only real threat-actor/malware names.

Regex-found indicators (give reason for each): {iocs}

ARTICLE:
{article}
"""

def ask_llm(article_text, iocs):
    try:
        resp = requests.post(OLLAMA_URL, json={
            "model": MODEL,
            "prompt": PROMPT.format(iocs=json.dumps(iocs), article=article_text[:4000]),
            "stream": False, "format": "json",
        }, timeout=300)
        return json.loads(resp.json()["response"])
    except Exception as e:
        print(f"    LLM error: {e}")
        return {}

def upsert_ioc(ioc_type, value, source, reason):
    if not value:
        return
    t = ioc_type.lower()
    v = value.lower() if t in ("domain","url","md5","sha1","sha256") else value
    cur.execute("""
        INSERT INTO iocs (ioc_type, value, reason, threat_type, confidence)
        VALUES (%s,%s,%s,'article',60)
        ON CONFLICT (ioc_type, value) DO UPDATE SET
            reason = COALESCE(iocs.reason, EXCLUDED.reason)
        RETURNING id
    """, (t, v, reason))
    ioc_id = cur.fetchone()[0]
    cur.execute("""SELECT 1 FROM ioc_sightings
                   WHERE ioc_id=%s AND source=%s AND seen_at::date=now()::date LIMIT 1""",
                (ioc_id, source))
    if cur.fetchone() is None:
        cur.execute("INSERT INTO ioc_sightings (ioc_id, source) VALUES (%s,%s)", (ioc_id, source))
        cur.execute("""UPDATE iocs SET times_seen=(SELECT COUNT(*) FROM ioc_sightings WHERE ioc_id=%s),
                       last_seen=now(), is_active=true WHERE id=%s""", (ioc_id, ioc_id))

def upsert_apt(name):
    if not name or name.lower() in ("unknown",""):
        return
    cur.execute("""
        INSERT INTO apt_groups (name) VALUES (%s)
        ON CONFLICT (name) DO UPDATE SET last_seen=now(),
            times_seen=apt_groups.times_seen+1
    """, (name,))


# --- latest 100 articles process karo (distinct on title, longest text) ---
cur.execute("""
    SELECT DISTINCT ON (data->>'title') id, data->>'title', data->>'link',
           data->>'published', data->>'text'
    FROM raw_items WHERE kind='article' AND processed=false
    ORDER BY data->>'title', LENGTH(data->>'text') DESC
""")
articles = cur.fetchall()
print(f"Processing {len(articles)} articles with LLM (CPU, thoda time lagega)...\n")

done = 0
for raw_id, title, link, published, text in articles:
    text = text or ""
    iocs = regex_iocs(text)
    intel = ask_llm(text, iocs)

    reasons = intel.get("ioc_reasons", {})
    apts = intel.get("apt_groups", [])
    malwares = intel.get("malware", [])
    summary = intel.get("summary", "")

    # article save
    cur.execute("""
        INSERT INTO articles (title, link, published, summary, apt_groups, malware)
        VALUES (%s,%s,%s,%s,%s,%s)
        ON CONFLICT (link) DO NOTHING
    """, (title, link, published, summary,
          apts if apts else None, malwares if malwares else None))

    # APT groups
    for a in apts:
        upsert_apt(a)

    # IOCs from this article (with LLM reason if available)
    for ioc_type, vals in iocs.items():
        for v in vals:
            reason = reasons.get(v) or f"Mentioned in article: {title[:50]}"
            upsert_ioc(ioc_type, v, "hackernews", reason)

    cur.execute("UPDATE raw_items SET processed=true WHERE source='hackernews' AND data->>'title'=%s", (title,))
    conn.commit()
    done += 1
    print(f"  [{done}/{len(articles)}] {title[:50]} | APT:{len(apts)} MAL:{len(malwares)} IOC:{sum(len(v) for v in iocs.values())}")

# Summary
cur.execute("SELECT COUNT(*) FROM articles"); print(f"\nArticles: {cur.fetchone()[0]}")
cur.execute("SELECT COUNT(*) FROM apt_groups"); print(f"APT groups: {cur.fetchone()[0]}")
cur.execute("SELECT COUNT(*) FROM iocs WHERE threat_type='article'"); print(f"Article IOCs: {cur.fetchone()[0]}")
cur.close(); conn.close()
