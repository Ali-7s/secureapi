ALTER TABLE alerts DROP CONSTRAINT alerts_fingerprint_key;
CREATE UNIQUE INDEX idx_alerts_fingerprint_unacked ON alerts (fingerprint) WHERE acknowledged_at IS NULL;
