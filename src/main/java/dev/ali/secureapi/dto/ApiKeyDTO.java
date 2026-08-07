package dev.ali.secureapi.dto;

import java.time.Instant;

public record ApiKeyDTO(Long id, String label, String keyPrefix, String scopes, Instant createdAt, Instant lastUsedAt,
                        Instant expiresAt, Instant revokedAt) {
}
