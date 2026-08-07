package dev.ali.secureapi.repository;


import dev.ali.secureapi.model.SecurityEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.util.HashMap;

@Slf4j
@Repository
public class SecurityEventRepository {
    private final JdbcClient jdbc;

    public SecurityEventRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void insert(SecurityEvent securityEvent) {
        String sql = """
                INSERT INTO security_events (event_type, principal, source_ip, details, created_at) VALUES (:event_type, :principal, CAST(:source_ip AS INET), :details::jsonb, :created_at)
                """;

        HashMap<String, Object> hashMap = new HashMap<>();
        hashMap.put("event_type", securityEvent.type().name());
        hashMap.put("principal", securityEvent.principal());
        hashMap.put("source_ip", securityEvent.ip());
        hashMap.put("details", securityEvent.details());
        hashMap.put("created_at", Timestamp.from(securityEvent.timestamp()));

        jdbc.sql(sql).params(hashMap).update();
    }
}
