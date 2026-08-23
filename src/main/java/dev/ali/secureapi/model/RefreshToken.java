package dev.ali.secureapi.model;

import java.time.Instant;

public record RefreshToken(Long id,
                           String jti,
                           Long userId,
                           Instant issuedAt,
                           Instant expiresAt,
                           Instant revokedAt,
                           String replacedBy) {
}
