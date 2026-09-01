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

RE_CVE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
RE_IP  = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

def valid_ip(s):
    try:
        ip = ipaddress.ip_address(s)
        return not (ip.is_private or ip.is_loopback or ip.is_reserved
                    or ip.is_multicast or ip.is_unspecified or ip.is_link_local)
    except ValueError:
        return False

PROMPT = """You are a cyber threat intelligence analyst. Read the article below and extract structured intel.

Return ONLY valid JSON (no markdown, no extra text) with this exact shape:
{{
  "apt_groups": ["names of threat actors / APT groups mentioned"],
  "malware": ["malware / tool names mentioned"],
  "campaign": "short campaign name or null",
  "target_sectors": ["sectors or countries targeted"],
  "ioc_context": [
    {{"ioc": "the indicator value", "type": "ip/domain/hash/cve", "malicious": true, "reason": "one line why this is malicious per the article"}}
  ],
  "summary": "2 line summary of the threat"
}}

Known indicators found by regex (give context/reason for these): {iocs}

ARTICLE:
{article}
"""

# Ek IP-waala article uthao (miniOrange)
cur.execute("""
    SELECT data->>'title', data->>'text'
    FROM raw_items WHERE kind='article'
    AND data->>'title' LIKE '%miniOrange%'
    ORDER BY LENGTH(data->>'text') DESC LIMIT 1
""")
title, text = cur.fetchone()
text = (text or "")[:4000]  # LLM ko itna dena kaafi

iocs = {
    "cve": sorted(set(RE_CVE.findall(text))),
    "ip": [ip for ip in sorted(set(RE_IP.findall(text))) if valid_ip(ip)],
}

print(f"Article: {title}\n")
print(f"Regex found: {iocs}\n")
print("Asking Ollama (thoda time lagega, CPU pe)...\n")

resp = requests.post(OLLAMA_URL, json={
    "model": MODEL,
    "prompt": PROMPT.format(iocs=json.dumps(iocs), article=text),
    "stream": False,
    "format": "json",
}, timeout=300)

result = resp.json()["response"]
print("=== LLM OUTPUT ===")
print(result)

cur.close()
conn.close()
