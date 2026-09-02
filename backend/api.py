import os
import psycopg2
import psycopg2.extras
from fastapi import FastAPI, Query, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from auth import verify_password, verify_totp, create_token, verify_token
from chatbot import chat_query

load_dotenv()

app = FastAPI(title="Threat Intel API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://192.168.15.100", "http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- DB ----------
def db():
    return psycopg2.connect(
        host=os.getenv("DB_HOST"), port=os.getenv("DB_PORT"),
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("API_DB_USER", os.getenv("DB_USER")),
        password=os.getenv("API_DB_PASSWORD", os.getenv("DB_PASSWORD")),
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

# ---------- AUTH ----------
class LoginReq(BaseModel):
    username: str
    password: str
    otp: str

@app.post("/login")
def login(req: LoginReq):
    admin_user = os.getenv("ADMIN_USER")
    pass_hash  = os.getenv("ADMIN_PASS_HASH")
    mfa_secret = os.getenv("MFA_SECRET")

    if req.username != admin_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(req.password, pass_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_totp(mfa_secret, req.otp):
        raise HTTPException(status_code=401, detail="Invalid OTP")

    return {"token": create_token(req.username)}

# dependency -- har protected endpoint ise use karega
def require_auth(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split(" ", 1)[1]
    user = verify_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return user


class ChatReq(BaseModel):
    question: str

@app.post("/chat")
def chat(req: ChatReq, user: str = Depends(require_auth)):
    return chat_query(req.question)

# ---------- PROTECTED ENDPOINTS ----------
@app.get("/stats")
def stats(user: str = Depends(require_auth)):
    return {
        "total_iocs":     query_one("SELECT COUNT(*) c FROM iocs")["c"],
        "active_iocs":    query_one("SELECT COUNT(*) c FROM iocs WHERE is_active=true")["c"],
        "recurring_iocs": query_one("SELECT COUNT(*) c FROM iocs WHERE times_seen>1")["c"],
        "total_cves":     query_one("SELECT COUNT(*) c FROM cves")["c"],
        "critical_cves":  query_one("SELECT COUNT(*) c FROM cves WHERE cvss_score>=9.0")["c"],
        "kev_cves":       query_one("SELECT COUNT(*) c FROM cves WHERE kev_listed=true")["c"],
        "articles":       query_one("SELECT COUNT(*) c FROM articles")["c"],
        "apt_groups":     query_one("SELECT COUNT(*) c FROM apt_groups")["c"],
        "risk_high":      query_one("SELECT COUNT(*) c FROM iocs WHERE risk_level='HIGH'")["c"],
        "risk_medium":    query_one("SELECT COUNT(*) c FROM iocs WHERE risk_level='MEDIUM'")["c"],
        "risk_low":       query_one("SELECT COUNT(*) c FROM iocs WHERE risk_level='LOW'")["c"],
    }

@app.get("/iocs")
def iocs(
    ioc_type: str = Query(None), source: str = Query(None),
    active_only: bool = Query(False), search: str = Query(None),
    limit: int = Query(50, le=200), offset: int = Query(0),
    user: str = Depends(require_auth),
):
    where = []; params = []
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
               i.risk_score, i.risk_level, i.first_seen, i.last_seen
        FROM iocs i {clause}
        ORDER BY i.times_seen DESC, i.last_seen DESC
        LIMIT %s OFFSET %s
    """, params + [limit, offset])
    return {"total": total, "limit": limit, "offset": offset, "data": rows}

@app.get("/iocs/recurring")
def recurring_iocs(limit: int = Query(20, le=100), user: str = Depends(require_auth)):
    return query("""
        SELECT id, ioc_type, value, malware, reason, times_seen, first_seen, last_seen
        FROM iocs WHERE times_seen>1
        ORDER BY times_seen DESC, last_seen DESC LIMIT %s
    """, [limit])

@app.get("/ioc/{value}")
def ioc_detail(value: str, user: str = Depends(require_auth)):
    ioc = query_one("SELECT * FROM iocs WHERE value=%s", [value])
    if not ioc:
        return {"error": "not found"}
    sightings = query("""
        SELECT source, seen_at FROM ioc_sightings WHERE ioc_id=%s ORDER BY seen_at DESC
    """, [ioc["id"]])
    enrichment = query_one("""
        SELECT abuse_score, abuse_reports, abuse_country, abuse_isp, abuse_usage,
               shodan_ports, shodan_org, enriched_at
        FROM ioc_enrichment WHERE ioc_id=%s
    """, [ioc["id"]])
    return {"ioc": ioc, "sightings": sightings, "enrichment": enrichment}

@app.get("/cves")
def cves(
    severity: str = Query(None), kev_only: bool = Query(False),
    min_cvss: float = Query(None), limit: int = Query(50, le=200), offset: int = Query(0),
    user: str = Depends(require_auth),
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
        FROM cves {clause} ORDER BY cvss_score DESC NULLS LAST LIMIT %s OFFSET %s
    """, params + [limit, offset])
    return {"total": total, "data": rows}

@app.get("/apt")
def apt(user: str = Depends(require_auth)):
    return query("SELECT * FROM apt_groups ORDER BY times_seen DESC, name")

@app.get("/articles")
def articles(limit: int = Query(30, le=100), user: str = Depends(require_auth)):
    return query("""
        SELECT title, link, published, summary, apt_groups, malware
        FROM articles ORDER BY id DESC LIMIT %s
    """, [limit])

@app.get("/charts/ioc-types")
def chart_ioc_types(user: str = Depends(require_auth)):
    return query("""
        SELECT ioc_type AS name, COUNT(*) AS value
        FROM iocs GROUP BY ioc_type ORDER BY value DESC
    """)

@app.get("/charts/severity")
def chart_severity(user: str = Depends(require_auth)):
    return query("""
        SELECT severity AS name, COUNT(*) AS value
        FROM cves WHERE severity IS NOT NULL GROUP BY severity ORDER BY value DESC
    """)
