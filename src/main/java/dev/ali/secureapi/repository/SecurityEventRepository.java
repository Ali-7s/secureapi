package dev.ali.secureapi.repository;


import dev.ali.secureapi.model.SecurityEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.util.Map;

@Slf4j
@Repository
public class SecurityEventRepository {
    private final JdbcClient jdbc;

    public SecurityEventRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public void insert(SecurityEvent securityEvent) {
        String sql = """
                INSERT INTO security_events (event_type, principal, source_ip, details, created_at) VALUES (:event_type, :principal, CAST(:source_ip AS INET), :details::jsonb, :created_at)
                """;
        jdbc.sql(sql).params(Map.of("event_type", securityEvent.type().name(), "principal", securityEvent.principal(), "source_ip", securityEvent.ip(), "details", securityEvent.details(), "created_at", Timestamp.from(securityEvent.timestamp()))).update();
    }
}
