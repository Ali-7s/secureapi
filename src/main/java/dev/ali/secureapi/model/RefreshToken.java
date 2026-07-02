package dev.ali.secureapi.model;

import java.time.Instant;

public record RefreshToken (Long id ,
                            String jti ,
                            Long userId,
                            Instant issuedAt,
                            Instant expiresAt,
                            Instant revokedAt,
                            String replacedBy) {
    // TODO: Possibly add logout_revoked boolean, tells whether revoke was caused by logout or not if replaced_by is ALSO null

}
