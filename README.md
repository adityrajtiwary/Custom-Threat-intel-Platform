# 🛡️ Custom Threat Intelligence Platform

> A self-hosted, AI-powered Cyber Threat Intelligence (CTI) platform that aggregates indicators from multiple public sources, deduplicates and enriches them, scores their risk, and surfaces everything through a secure, interactive dashboard with a natural-language query assistant.

![Python](https://img.shields.io/badge/Python-3.12-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-backend-009688)
![React](https://img.shields.io/badge/React-dashboard-61dafb)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791)
![Ollama](https://img.shields.io/badge/LLM-Ollama_llama3.2-black)
![Security](https://img.shields.io/badge/Auth-MFA_%2B_TLS-red)

---

## 📖 Overview

This platform automates the full CTI lifecycle: **collect → normalize → enrich → score → serve**. It pulls threat data from five public feeds, resolves it into a clean, deduplicated database with a **sighting-tracking model** (so a recurring indicator is recorded, not duplicated), enriches indicators using **third-party reputation/infrastructure APIs** and a **local LLM**, assigns each indicator a **composite risk score**, and presents everything through an authenticated HTTPS dashboard — including an **"ask your data" chatbot** that converts plain-English questions into safe SQL.

Built end-to-end as a hands-on SOC/DevSecOps project: data engineering, backend APIs, frontend, enrichment, automation, and production-grade security hardening.

---

## 📸 Screenshots

### Secure Login (MFA + TLS)
![Login](docs/login.png)

### Threat Intelligence Dashboard
![Dashboard](docs/dashboard.png)

### AI Chatbot — Ask Your Data
![Chatbot](docs/chatbot.png)

### IOC Explorer + Enrichment Detail
![IOCs](docs/iocs.png)

### APT Groups
![APT Groups](docs/apt.png)

### Threat Feed
![Threat Feed](docs/threat-feed.png)

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| **Multi-source ingestion** | ransomware.live, abuse.ch ThreatFox, CISA KEV, NVD, The Hacker News |
| **Deduplication + Sightings** | Canonical normalization (defang, lowercase, port-strip) + recurring-indicator tracking |
| **IOC enrichment** | AbuseIPDB (reputation, reports, country, ISP) + Shodan (open ports, hosting org) |
| **Composite risk scoring** | Multi-signal score (feed + abuse + suspicious ports + sightings) → HIGH / MEDIUM / LOW |
| **LLM enrichment** | Local Ollama (llama3.2) extracts APT groups, malware, and per-IOC reasoning from articles |
| **CVE intelligence** | CVSS + severity (NVD) combined with actively-exploited flags (CISA KEV) |
| **Interactive dashboard** | React SPA with drill-down, charts, risk breakdown, enrichment detail panels |
| **AI chatbot** | Natural-language → SQL over the threat database (read-only, validated) |
| **Full automation** | Cron pipeline: ingest → process → enrich → score, daily, with per-run logging |

---

## 🎯 Composite Risk Scoring

A key design decision: **no single source is trusted alone.** An IP can score `0%` on AbuseIPDB (no community reports) yet still be a live C2 server. The platform combines multiple signals into one risk score:

```
risk = feed_presence (30)
     + abuse_score × 0.4        (AbuseIPDB reputation)
     + suspicious_ports (20)    (e.g. 4444, exposed RDP/SMB)
     + recurring (15)           (seen multiple times / sources)
     + source_confidence × 0.15
  → 0–100  →  HIGH / MEDIUM / LOW
```

**Example:** an IP with `0%` AbuseIPDB score but tagged as a RAT C2 in the feed, with port `4444` open on Shodan, seen twice → scored **HIGH**. This cross-source correlation catches threats a single reputation lookup would miss.

---

## 🏗️ Architecture

```
                 ┌──────────── SOURCES ────────────┐
                 │ ransomware.live · ThreatFox      │
                 │ CISA KEV · NVD · Hacker News     │
                 └────────────────┬─────────────────┘
                                  │  (cron, daily 08:00)
                                  ▼
                        ┌──────────────────┐
                        │   Connectors     │  raw JSONB landing
                        └────────┬─────────┘
                                 ▼
                        ┌──────────────────┐
                        │   Processors     │  normalize · dedup · sightings
                        │  + Ollama (LLM)  │  APT / malware / reasoning
                        └────────┬─────────┘
                                 ▼
                        ┌──────────────────┐
                        │   Enrichment     │  AbuseIPDB · Shodan
                        │   + Risk Scoring │  composite HIGH/MED/LOW
                        └────────┬─────────┘
                                 ▼
                     ┌────────────────────────┐
                     │   PostgreSQL           │  iocs · cves · articles
                     │   (clean, indexed)     │  apt_groups · sightings · enrichment
                     └───────┬────────────────┘
                             │  (read-only user)
                             ▼
                     ┌────────────────┐        ┌──────────────┐
                     │  FastAPI       │◄───────│  Ollama      │  text-to-SQL
                     │  (auth+MFA)    │        │  (chatbot)   │
                     └───────┬────────┘        └──────────────┘
                             │  HTTPS / JWT
                             ▼
                     ┌────────────────┐
                     │  nginx (TLS)   │  reverse proxy + static
                     └───────┬────────┘
                             ▼
                     ┌────────────────┐
                     │  React SPA     │  dashboard + chatbot
                     └────────────────┘
```

---

## 🔐 Security (DevSecOps)

Security was treated as a first-class concern, not an afterthought:

- **Authentication** — username + bcrypt-hashed password
- **MFA** — TOTP (Google Authenticator / Authy), out-of-band second factor
- **JWT** — signed, expiring session tokens
- **TLS/HTTPS** — all traffic encrypted (nginx reverse proxy)
- **Least privilege** — API + chatbot use a dedicated **read-only** database role; connectors use a separate write role
- **Chatbot safety** — SELECT-only validation, forbidden-keyword blocking, single-statement enforcement, query timeout
- **CORS lockdown** — API accepts only the dashboard origin
- **Security headers** — anti-clickjacking, MIME-sniffing protection
- **Rate-limit-aware enrichment** — batched, throttled API calls with graceful 429 handling
- **Secrets hygiene** — no secrets in the repo; `.env` git-ignored, `.env.example` provided

---

## 🧰 Tech Stack

**Backend:** Python, FastAPI, psycopg2, python-jose (JWT), bcrypt, pyotp (MFA)
**Frontend:** React (Vite), Recharts, lucide-react, axios
**Data:** PostgreSQL 16, JSONB landing zone
**Enrichment:** AbuseIPDB API, Shodan API
**AI:** Ollama (llama3.2) — local, offline, free
**Infra:** Docker (Postgres/Ollama), nginx (TLS), systemd, cron

---

## 📊 Data Model Highlights

- **Raw landing zone** (`raw_items`, JSONB) — source of truth, never mutated
- **`iocs`** — deduplicated on `(ioc_type, value)`, with `times_seen`, `first/last_seen`, `is_active`, `risk_score`, `risk_level`
- **`ioc_sightings`** — every observation logged (source + timestamp)
- **`ioc_enrichment`** — AbuseIPDB + Shodan data per indicator
- **`cves`** — CVSS + severity + KEV flag
- **`articles` / `apt_groups`** — LLM-extracted intel

---

## 🚀 Getting Started

> Prerequisites: Docker, Python 3.12, Node.js 20, Ollama with `llama3.2`

```bash
# 1. Backend
cd backend
cp .env.example .env          # fill in DB + API keys
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn api:app --host 0.0.0.0 --port 8000

# 2. Admin + MFA setup
python setup_admin.py          # sets password, prints MFA QR

# 3. Frontend
cd ../frontend
cp .env.example .env
npm install && npm run build

# 4. Run the full pipeline (ingest → process → enrich → score)
./run_pipeline.sh
```

---

## 🗺️ Roadmap

- [x] Multi-source ingestion + dedup + sightings
- [x] LLM enrichment (Ollama)
- [x] AbuseIPDB + Shodan enrichment
- [x] Composite risk scoring (HIGH/MED/LOW)
- [x] Authenticated dashboard (MFA + TLS)
- [x] Natural-language chatbot
- [x] Full automation (daily cron pipeline)
- [ ] MITRE ATT&CK technique mapping
- [ ] STIX/TAXII + firewall blocklist export
- [ ] Time-series threat trends
- [ ] n8n AI workflows (daily brief, smart alerts)

---

## 📝 Notes

Personal learning + portfolio project demonstrating the full CTI engineering lifecycle — from raw feed ingestion to a secured, AI-assisted analyst interface with automated enrichment and risk scoring. All data sources are public and used within their terms.

---

*Built by [Aditya Raj](https://github.com/adityrajtiwary) 
