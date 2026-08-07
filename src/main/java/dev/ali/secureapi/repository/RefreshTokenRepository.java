package dev.ali.secureapi.repository;

import dev.ali.secureapi.model.RefreshToken;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Map;

@Repository
@Slf4j
public class RefreshTokenRepository {
    private final JdbcClient jdbc;


    public RefreshTokenRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }


    public void insert(Long userId, String jti, Instant expiresAt, Instant issuedAt) {
        String sql = "INSERT INTO refresh_tokens (user_id, jti, expires_at, issued_at) VALUES (:user_id, :jti, :expires_at, :issued_at)";
        jdbc.sql(sql).params(Map.of("user_id", userId, "jti", jti, "expires_at", Timestamp.from(expiresAt), "issued_at", Timestamp.from(issuedAt))).update();
    }

    public RefreshToken findByJti(String jti) {
        String sql = "SELECT * FROM refresh_tokens WHERE jti = :jti";
        return jdbc.sql(sql).param("jti", jti).query(RefreshToken.class).single();
    }

    public void revoke(String jti, String replacedByJti) {
        String sql = "UPDATE refresh_tokens SET replaced_by = :replaced_by, revoked_at = :revoked_at WHERE jti = :jti AND revoked_at IS NULL";
        jdbc.sql(sql).params(Map.of("jti", jti, "replaced_by", replacedByJti, "revoked_at", Timestamp.from(Instant.now()))).update();
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void revoke(Long userId) {
        String sql = "UPDATE refresh_tokens SET revoked_at = :revoked_at WHERE user_id = :userId AND revoked_at IS NULL";
        int rowsAffected = jdbc.sql(sql).params(Map.of("userId", userId.intValue(), "revoked_at", Timestamp.from(Instant.now()))).update();
        log.info("Rows affected: {}", rowsAffected);
    }
}
