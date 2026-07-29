package dev.ali.secureapi.model;

import java.time.Instant;

public record Alert(Long id, String ruleName, String severity, String fingerprint, String suppressUntil, Instant createdAt, Instant acknowledgedAt) {
}
