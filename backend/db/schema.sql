-- Home Radar SQLite schema: devices, events, alerts, traffic_logs, trust_scores

CREATE TABLE IF NOT EXISTS devices (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    mac             TEXT NOT NULL UNIQUE,
    ip              TEXT,
    hostname        TEXT,
    vendor          TEXT,
    model           TEXT,
    device_type     TEXT DEFAULT 'unknown',
    fingerprint_confidence REAL DEFAULT 0,
    open_ports      TEXT,               -- JSON-encoded list of ints
    services        TEXT,               -- JSON-encoded advertised services
    discovery_sources TEXT,             -- JSON-encoded source names
    fingerprint     TEXT,               -- JSON-encoded evidence and signal scores
    trust_score     INTEGER DEFAULT 50,
    is_authorized   INTEGER DEFAULT 0,  -- 0 = pending, 1 = authorized, 2 = blocked
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       INTEGER REFERENCES devices(id),
    event_type      TEXT NOT NULL,      -- e.g. 'new_device', 'ip_changed', 'reconnected'
    detail          TEXT,
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       INTEGER REFERENCES devices(id),
    severity        TEXT NOT NULL DEFAULT 'info',  -- info | warning | critical
    title           TEXT NOT NULL,
    description     TEXT,
    is_resolved     INTEGER DEFAULT 0,
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS traffic_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       INTEGER REFERENCES devices(id),
    domain          TEXT,
    dest_ip         TEXT,
    bytes_sent      INTEGER DEFAULT 0,
    bytes_received  INTEGER DEFAULT 0,
    was_blocked     INTEGER DEFAULT 0,
    threat_level    TEXT DEFAULT 'none',
    threat_reason   TEXT,
    query_type      TEXT,
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS trust_scores (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       INTEGER REFERENCES devices(id),
    score           INTEGER NOT NULL,
    reason          TEXT,
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key             TEXT PRIMARY KEY,
    value           TEXT,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threat_cache (
    indicator       TEXT NOT NULL,
    indicator_type  TEXT NOT NULL,
    is_malicious    INTEGER NOT NULL DEFAULT 0,
    confidence      INTEGER NOT NULL DEFAULT 0,
    source          TEXT NOT NULL,
    detail          TEXT,
    expires_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    PRIMARY KEY (indicator, indicator_type, source)
);

CREATE TABLE IF NOT EXISTS blocklist_metadata (
    source          TEXT PRIMARY KEY,
    domain_count    INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL,
    error           TEXT,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cisa_kev (
    cve_id          TEXT PRIMARY KEY,
    vendor_project  TEXT,
    product         TEXT,
    vulnerability_name TEXT,
    date_added      TEXT,
    due_date        TEXT,
    ransomware_use  TEXT,
    required_action TEXT,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS behavior_baselines (
    device_id       INTEGER NOT NULL REFERENCES devices(id),
    metric          TEXT NOT NULL,
    mean            REAL NOT NULL DEFAULT 0,
    variance        REAL NOT NULL DEFAULT 0,
    samples         INTEGER NOT NULL DEFAULT 0,
    updated_at      TEXT NOT NULL,
    PRIMARY KEY (device_id, metric)
);

CREATE TABLE IF NOT EXISTS device_policies (
    device_id       INTEGER PRIMARY KEY REFERENCES devices(id),
    internet_enabled INTEGER NOT NULL DEFAULT 1,
    block_start     TEXT,
    block_end       TEXT,
    blocked_domains TEXT,
    allowed_domains TEXT,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS exposure_findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       INTEGER NOT NULL REFERENCES devices(id),
    finding_key     TEXT NOT NULL,
    severity        TEXT NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,
    recommendation  TEXT NOT NULL,
    evidence        TEXT,
    is_resolved     INTEGER NOT NULL DEFAULT 0,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    UNIQUE(device_id, finding_key)
);

CREATE INDEX IF NOT EXISTS idx_events_device ON events(device_id);
CREATE INDEX IF NOT EXISTS idx_alerts_device ON alerts(device_id);
CREATE INDEX IF NOT EXISTS idx_traffic_device ON traffic_logs(device_id);
CREATE INDEX IF NOT EXISTS idx_trust_scores_device ON trust_scores(device_id);
CREATE INDEX IF NOT EXISTS idx_devices_type ON devices(device_type);
CREATE INDEX IF NOT EXISTS idx_devices_vendor ON devices(vendor);
CREATE INDEX IF NOT EXISTS idx_traffic_created ON traffic_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_traffic_domain ON traffic_logs(domain);
CREATE INDEX IF NOT EXISTS idx_traffic_blocked ON traffic_logs(was_blocked);
CREATE INDEX IF NOT EXISTS idx_alerts_resolved_created ON alerts(is_resolved, created_at);
CREATE INDEX IF NOT EXISTS idx_findings_device ON exposure_findings(device_id);
CREATE INDEX IF NOT EXISTS idx_findings_open ON exposure_findings(is_resolved, severity);
