import os
import json
import time
import hashlib
import requests
import feedparser
import psycopg2
from bs4 import BeautifulSoup
from dotenv import load_dotenv

load_dotenv()

FEED_URL = "https://feeds.feedburner.com/TheHackersNews"
HEADERS = {"User-Agent": "Mozilla/5.0 (threat-intel-collector)"}

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
        ("hackernews", kind, json.dumps(payload), h),
    )
    return cur.rowcount == 1

def fetch_full_article(url):
    """Article page se poora body text nikaalo."""
    try:
        r = requests.get(url, headers=HEADERS, timeout=30)
        if r.status_code != 200:
            return None
        soup = BeautifulSoup(r.text, "lxml")
        # HackerNews ka article body is div me hota hai
        body = soup.select_one("div.articlebody") or soup.select_one("div.post-body")
        if not body:
            return None
        for tag in body(["script", "style"]):
            tag.decompose()
        return body.get_text(separator=" ", strip=True)
    except Exception as e:
        print(f"    fetch error: {e}")
        return None

print(f"Fetching feed: {FEED_URL}")
feed = feedparser.parse(FEED_URL)
print(f"Found {len(feed.entries)} articles in feed\n")

inserted = 0
for i, entry in enumerate(feed.entries, 1):
    title = entry.get("title", "")
    link = entry.get("link", "")
    published = entry.get("published", "")

    full_text = fetch_full_article(link)
    if not full_text:
        # fallback: RSS summary
        full_text = BeautifulSoup(entry.get("summary", ""), "lxml").get_text(strip=True)

    article = {
        "title": title,
        "link": link,
        "published": published,
        "text": full_text,
    }
    if insert_raw("article", article):
        inserted += 1
    print(f"  [{i}/{len(feed.entries)}] {len(full_text or '')} chars | {title[:50]}")
    time.sleep(1)  # polite delay, server pe load na pade

conn.commit()
print(f"\nDone. New articles inserted: {inserted}")
cur.close()
conn.close()
