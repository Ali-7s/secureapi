CREATE TABLE IF NOT EXISTS security_events (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    principal VARCHAR(255),
    source_ip INET NOT NULL,
    details JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_security_events_ip_type ON security_events (source_ip, event_type);

CREATE TABLE alerts(
    id SERIAL PRIMARY KEY,
    rule_name VARCHAR(500) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    fingerprint VARCHAR(255) UNIQUE NOT NULL,
    suppress_until TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
)