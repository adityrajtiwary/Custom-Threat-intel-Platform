-- ============ IOCS (core, deduplicated) ============
CREATE TABLE IF NOT EXISTS iocs (
    id            BIGSERIAL PRIMARY KEY,
    ioc_type      TEXT NOT NULL,        -- ip, domain, url, md5, sha256, etc.
    value         TEXT NOT NULL,
    malware       TEXT,                 -- kis malware se juda (threatfox se)
    threat_type   TEXT,                 -- botnet_cc, payload, etc.
    reason        TEXT,                 -- kyun malicious (LLM/threatfox se)
    confidence    INT DEFAULT 50,
    first_seen    TIMESTAMPTZ DEFAULT now(),
    last_seen     TIMESTAMPTZ DEFAULT now(),
    times_seen    INT DEFAULT 1,
    is_active     BOOLEAN DEFAULT true,
    UNIQUE (ioc_type, value)            -- yahi dedup: same IOC ek hi baar
);

-- ============ SIGHTINGS (har baar dikhne ka record) ============
CREATE TABLE IF NOT EXISTS ioc_sightings (
    id           BIGSERIAL PRIMARY KEY,
    ioc_id       BIGINT REFERENCES iocs(id) ON DELETE CASCADE,
    source       TEXT NOT NULL,         -- kahan dikha
    seen_at      TIMESTAMPTZ DEFAULT now(),
    raw_item_id  BIGINT                 -- kis pull se aaya
);

-- ============ CVES ============
CREATE TABLE IF NOT EXISTS cves (
    id             BIGSERIAL PRIMARY KEY,
    cve_id         TEXT UNIQUE NOT NULL,
    cvss_score     NUMERIC,
    severity       TEXT,
    description    TEXT,
    kev_listed     BOOLEAN DEFAULT false,  -- CISA KEV mein hai? (actively exploited)
    published      TIMESTAMPTZ,
    first_seen     TIMESTAMPTZ DEFAULT now(),
    last_seen      TIMESTAMPTZ DEFAULT now()
);

-- ============ ARTICLES ============
CREATE TABLE IF NOT EXISTS articles (
    id           BIGSERIAL PRIMARY KEY,
    title        TEXT NOT NULL,
    link         TEXT UNIQUE,
    published    TEXT,
    summary      TEXT,                  -- LLM ka 2-line summary
    apt_groups   TEXT[],                -- nikale gaye APT groups
    malware      TEXT[],                -- nikale gaye malware
    fetched_at   TIMESTAMPTZ DEFAULT now()
);

-- ============ APT GROUPS ============
CREATE TABLE IF NOT EXISTS apt_groups (
    id           BIGSERIAL PRIMARY KEY,
    name         TEXT UNIQUE NOT NULL,
    first_seen   TIMESTAMPTZ DEFAULT now(),
    last_seen    TIMESTAMPTZ DEFAULT now(),
    times_seen   INT DEFAULT 1
);

-- Indexes for speed
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_iocs_active ON iocs(is_active);
CREATE INDEX IF NOT EXISTS idx_iocs_malware ON iocs(malware);
CREATE INDEX IF NOT EXISTS idx_sightings_ioc ON ioc_sightings(ioc_id);
CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
