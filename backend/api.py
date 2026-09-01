import os
import psycopg2
import psycopg2.extras
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Threat Intel API")

# CORS -- React (browser) se call ho sake
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # dev ke liye sab allow; production me specific origin
    allow_methods=["*"],
    allow_headers=["*"],
)

def db():
    return psycopg2.connect(
        host=os.getenv("DB_HOST"), port=os.getenv("DB_PORT"),
        dbname=os.getenv("DB_NAME"), user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        cursor_factory=psycopg2.extras.RealDictCursor,
    )

def query(sql, params=None):
    conn = db(); cur = conn.cursor()
    cur.execute(sql, params or ())
    rows = cur.fetchall()
    cur.close(); conn.close()
    return rows

def query_one(sql, params=None):
    rows = query(sql, params)
    return rows[0] if rows else None


@app.get("/stats")
def stats():
    return {
        "total_iocs":     query_one("SELECT COUNT(*) c FROM iocs")["c"],
        "active_iocs":    query_one("SELECT COUNT(*) c FROM iocs WHERE is_active=true")["c"],
        "recurring_iocs": query_one("SELECT COUNT(*) c FROM iocs WHERE times_seen>1")["c"],
        "total_cves":     query_one("SELECT COUNT(*) c FROM cves")["c"],
        "critical_cves":  query_one("SELECT COUNT(*) c FROM cves WHERE cvss_score>=9.0")["c"],
        "kev_cves":       query_one("SELECT COUNT(*) c FROM cves WHERE kev_listed=true")["c"],
        "articles":       query_one("SELECT COUNT(*) c FROM articles")["c"],
        "apt_groups":     query_one("SELECT COUNT(*) c FROM apt_groups")["c"],
    }


@app.get("/iocs")
def iocs(
    ioc_type: str = Query(None),
    source: str = Query(None),
    active_only: bool = Query(False),
    search: str = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0),
):
    where = []
    params = []
    if ioc_type:
        where.append("i.ioc_type=%s"); params.append(ioc_type)
    if active_only:
        where.append("i.is_active=true")
    if search:
        where.append("i.value ILIKE %s"); params.append(f"%{search}%")
    if source:
        where.append("EXISTS (SELECT 1 FROM ioc_sightings s WHERE s.ioc_id=i.id AND s.source=%s)")
        params.append(source)
    clause = ("WHERE " + " AND ".join(where)) if where else ""

    total = query_one(f"SELECT COUNT(*) c FROM iocs i {clause}", params)["c"]
    rows = query(f"""
        SELECT i.id, i.ioc_type, i.value, i.malware, i.threat_type,
               i.reason, i.confidence, i.times_seen, i.is_active,
               i.first_seen, i.last_seen
        FROM iocs i {clause}
        ORDER BY i.times_seen DESC, i.last_seen DESC
        LIMIT %s OFFSET %s
    """, params + [limit, offset])
    return {"total": total, "limit": limit, "offset": offset, "data": rows}


@app.get("/iocs/recurring")
def recurring_iocs(limit: int = Query(20, le=100)):
    return query("""
        SELECT id, ioc_type, value, malware, reason, times_seen,
               first_seen, last_seen
        FROM iocs WHERE times_seen>1
        ORDER BY times_seen DESC, last_seen DESC
        LIMIT %s
    """, [limit])


@app.get("/ioc/{value}")
def ioc_detail(value: str):
    ioc = query_one("SELECT * FROM iocs WHERE value=%s", [value])
    if not ioc:
        return {"error": "not found"}
    sightings = query("""
        SELECT source, seen_at FROM ioc_sightings
        WHERE ioc_id=%s ORDER BY seen_at DESC
    """, [ioc["id"]])
    return {"ioc": ioc, "sightings": sightings}


@app.get("/cves")
def cves(
    severity: str = Query(None),
    kev_only: bool = Query(False),
    min_cvss: float = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0),
):
    where = []; params = []
    if severity:
        where.append("severity=%s"); params.append(severity.upper())
    if kev_only:
        where.append("kev_listed=true")
    if min_cvss is not None:
        where.append("cvss_score>=%s"); params.append(min_cvss)
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    total = query_one(f"SELECT COUNT(*) c FROM cves {clause}", params)["c"]
    rows = query(f"""
        SELECT cve_id, cvss_score, severity, description, kev_listed, published
        FROM cves {clause}
        ORDER BY cvss_score DESC NULLS LAST
        LIMIT %s OFFSET %s
    """, params + [limit, offset])
    return {"total": total, "data": rows}


@app.get("/apt")
def apt():
    return query("SELECT * FROM apt_groups ORDER BY times_seen DESC, name")


@app.get("/articles")
def articles(limit: int = Query(30, le=100)):
    return query("""
        SELECT title, link, published, summary, apt_groups, malware
        FROM articles ORDER BY id DESC LIMIT %s
    """, [limit])


@app.get("/charts/ioc-types")
def chart_ioc_types():
    return query("""
        SELECT ioc_type AS name, COUNT(*) AS value
        FROM iocs GROUP BY ioc_type ORDER BY value DESC
    """)


@app.get("/charts/severity")
def chart_severity():
    return query("""
        SELECT severity AS name, COUNT(*) AS value
        FROM cves WHERE severity IS NOT NULL
        GROUP BY severity ORDER BY value DESC
    """)
