package dev.ali.secureapi.model;

import java.time.Instant;

public record ApiKey(Long id, Long userId, String label, String keyPrefix, String keyHash, String scopes,
                     Instant createdAt, Instant lastUsedAt, Instant expiresAt, Instant revokedAt) {
}
