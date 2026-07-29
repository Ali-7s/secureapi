package dev.ali.secureapi.repository;

import dev.ali.secureapi.dto.ApiKeyDTO;
import dev.ali.secureapi.model.ApiKey;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Repository
public class ApiKeyRepository {
    private final JdbcClient jdbc;

    public ApiKeyRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }


    public Long insert(Long userId, String label, String keyPrefix, String keyHash, String scopes, Instant expiresAt) {
       String sql = "INSERT INTO api_keys(user_id, label, key_prefix, key_hash, scopes, expires_at) VALUES (:user_id, :label, :key_prefix, :key_hash, :scopes, :expires_at) RETURNING id";
        return jdbc.sql(sql).params(Map.of("user_id", userId, "label", label, "key_prefix", keyPrefix, "key_hash", keyHash, "scopes", scopes, "expires_at", Timestamp.from(expiresAt))).query(Long.class).single();
    }

    public List<ApiKeyDTO> findByUserId(Long userId) {
        String sql = "SELECT id, label, key_prefix, scopes, created_at, last_used_at, expires_at, revoked_at FROM api_keys WHERE user_id = :userId";
        // Return all,revoked or not
        return jdbc.sql(sql).param("userId", userId).query(ApiKeyDTO.class).list();
    }

    public Long findOwnerId(Long keyId) {
        String sql = "SELECT user_id FROM api_keys WHERE id = :keyId";

        return jdbc.sql(sql).param("keyId", keyId).query(Long.class).single();
    }

    public int revokeByIdAndOwner(Long keyId, Long ownerId) {
        String sql = "UPDATE api_keys SET revoked_at = now() WHERE id = :keyId AND user_id = :ownerId AND revoked_at ISNULL";
        return jdbc.sql(sql).params(Map.of("keyId", keyId, "ownerId", ownerId)).update();
    }

    public Optional<ApiKey> findActiveByHash(String keyHash) {
        String sql = "SELECT * FROM api_keys WHERE key_hash = :keyHash AND revoked_at IS NULL AND expires_at > now()";
        return jdbc.sql(sql).param("keyHash", keyHash).query(ApiKey.class).optional();
    }

    public int updateLastUsed(Long keyId) {
        String sql = "UPDATE api_keys SET last_used_at = NOW() WHERE id = :keyId AND revoked_at ISNULL";
        return jdbc.sql(sql).param("keyId", keyId).update();
    }
}
