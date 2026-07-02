package dev.ali.secureapi.model;

import java.time.Instant;

public record Alert(String ruleName, String severity, String fingerprint, String suppressUntil, Instant createdAt) {
    public Alert(String ruleName, String severity, String fingerprint, String suppressUntil) {
        this(ruleName, severity, fingerprint, suppressUntil, Instant.now());
    }
}
