package dev.ali.secureapi.repository;

import dev.ali.secureapi.model.Alert;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.util.Map;

@Repository
public class AlertRepository {
    private final JdbcClient jdbc;


    public AlertRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public void insert(Alert alert) {
        String sql = """
                INSERT INTO alerts(rule_name, severity, fingerprint, suppress_until) VALUES (:rule_name, :severity, :fingerprint, now() + CAST(:suppress_until AS INTERVAL)) ON CONFLICT (fingerprint) DO UPDATE SET suppress_until = excluded.suppress_until;
               
                """;
        jdbc.sql(sql).params(Map.of("rule_name", alert.ruleName(), "severity", alert.severity(), "fingerprint", alert.fingerprint(), "suppress_until", alert.suppressUntil())).update();

    }
}