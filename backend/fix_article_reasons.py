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

# saare articles (title -> summary) memory me lo
cur.execute("SELECT title, summary FROM articles WHERE summary IS NOT NULL AND summary <> ''")
title_summary = {t: s for t, s in cur.fetchall()}
print(f"Loaded {len(title_summary)} article summaries")

# saari article IOCs jinka reason generic hai
cur.execute("""SELECT id, reason FROM iocs
               WHERE threat_type='article' AND reason LIKE 'Mentioned in article:%'""")
rows = cur.fetchall()
print(f"Fixing {len(rows)} article IOCs")

fixed = 0
for ioc_id, reason in rows:
    # reason format: "Mentioned in article: <title first 50 chars>"
    title_frag = reason.replace("Mentioned in article: ", "").strip()
    # matching article dhundo (title jo is fragment se shuru hota hai)
    match = None
    for title, summary in title_summary.items():
        if title.startswith(title_frag[:40]):
            match = summary
            break
    if match:
        cur.execute("UPDATE iocs SET reason=%s WHERE id=%s", (match, ioc_id))
        fixed += 1

conn.commit()
print(f"Updated {fixed} IOCs with article summary as reason")
cur.close(); conn.close()
