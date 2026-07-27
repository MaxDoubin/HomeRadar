-- HomeSentry SQLite schema: devices, events, alerts, traffic_logs, trust_scores

CREATE TABLE IF NOT EXISTS devices (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    mac             TEXT NOT NULL UNIQUE,
    ip              TEXT,
    hostname        TEXT,
    vendor          TEXT,
    device_type     TEXT DEFAULT 'unknown',
    open_ports      TEXT,               -- JSON-encoded list of ints
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
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS trust_scores (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       INTEGER REFERENCES devices(id),
    score           INTEGER NOT NULL,
    reason          TEXT,
    created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_device ON events(device_id);
CREATE INDEX IF NOT EXISTS idx_alerts_device ON alerts(device_id);
CREATE INDEX IF NOT EXISTS idx_traffic_device ON traffic_logs(device_id);
CREATE INDEX IF NOT EXISTS idx_trust_scores_device ON trust_scores(device_id);
