package dev.ali.secureapi.repository;


import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.Optional;

@Repository
public class LockoutServiceRepository {
    private final JdbcClient jdbc;

    public LockoutServiceRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }


    public Optional<OffsetDateTime> findLockedUntil(String principal) {
        String sql = "SELECT locked_until FROM account_lockouts WHERE principal = :principal";
        return jdbc.sql(sql).param("principal", principal).query(OffsetDateTime.class).optional();
    }

    public void upsertLock(String principal, String lockFor) {
        String sql = "INSERT INTO account_lockouts (principal, locked_until) VALUES (:principal, now() + CAST(:locked_until AS INTERVAL)) ON CONFLICT (principal) DO UPDATE SET locked_until = excluded.locked_until";
         jdbc.sql(sql).params(Map.of("principal", principal,  "locked_until", lockFor)).update();

    }
}
