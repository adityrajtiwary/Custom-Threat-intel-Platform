import os
import re
import ipaddress
import psycopg2
from dotenv import load_dotenv

load_dotenv()

conn = psycopg2.connect(
    host=os.getenv("DB_HOST"), port=os.getenv("DB_PORT"),
    dbname=os.getenv("DB_NAME"), user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
)
cur = conn.cursor()

RE_CVE    = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
RE_IP     = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
RE_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
RE_SHA1   = re.compile(r'\b[a-fA-F0-9]{40}\b')
RE_MD5    = re.compile(r'\b[a-fA-F0-9]{32}\b')

# Jaani-maani legit domains/infra jo IOC nahi hote
BENIGN_DOMAINS = {
    "google.com", "microsoft.com", "github.com", "thehackernews.com",
    "feedburner.com", "cloudflare.com", "amazonaws.com", "cisa.gov",
    "twitter.com", "x.com", "facebook.com", "youtube.com", "linkedin.com",
}

def is_valid_public_ip(ip_str):
    """Sirf valid, public, routable IP -> True. Baaki sab reject."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False  # galat IP (jaise version number 1.2.3.4 jo range se bahar)
    # ye sab reject karo
    if (ip.is_private or ip.is_loopback or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified or ip.is_link_local):
        return False
    return True

def extract_iocs(text):
    ips = sorted(set(RE_IP.findall(text)))
    clean_ips = [ip for ip in ips if is_valid_public_ip(ip)]
    return {
        "cve":    sorted(set(RE_CVE.findall(text))),
        "ip":     clean_ips,
        "sha256": sorted(set(RE_SHA256.findall(text))),
        "sha1":   sorted(set(RE_SHA1.findall(text))),
        "md5":    sorted(set(RE_MD5.findall(text))),
    }

cur.execute("""
    SELECT DISTINCT ON (data->>'title') data->>'title', data->>'text'
    FROM raw_items WHERE kind='article'
    ORDER BY data->>'title', LENGTH(data->>'text') DESC
    LIMIT 10
""")

for title, text in cur.fetchall():
    text = text or ""
    iocs = extract_iocs(text)
    found = {k: v for k, v in iocs.items() if v}
    if found:
        print(f"\n=== {title[:60]} ===")
        for t, vals in found.items():
            print(f"  {t}: {vals[:6]}{' ...' if len(vals)>6 else ''}")

cur.close()
conn.close()
