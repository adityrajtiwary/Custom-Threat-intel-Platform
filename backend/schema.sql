-- Raw landing zone: har source ka data jaisa aata hai waisa gir jaata hai
CREATE TABLE IF NOT EXISTS raw_items (
    id           BIGSERIAL PRIMARY KEY,
    source       TEXT NOT NULL,           -- 'ransomware.live', 'hackernews', etc.
    kind         TEXT,                    -- 'victim', 'article', 'cve'... (jab pata chale)
    data         JSONB NOT NULL,          -- poora raw payload, koi bhi shape
    content_hash TEXT UNIQUE,             -- dedup ke liye
    fetched_at   TIMESTAMPTZ DEFAULT now(),
    processed    BOOLEAN DEFAULT false    -- baad me LLM/parsing ne process kiya ya nahi
);

CREATE INDEX IF NOT EXISTS idx_raw_source ON raw_items(source);
CREATE INDEX IF NOT EXISTS idx_raw_processed ON raw_items(processed);
CREATE INDEX IF NOT EXISTS idx_raw_data ON raw_items USING GIN (data);
