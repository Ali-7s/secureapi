package dev.ali.secureapi.repository;

import dev.ali.secureapi.model.Alert;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Map;

@Repository
public class AlertRepository {
    private final JdbcClient jdbc;


    public AlertRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public Long insert(String ruleName, String severity, String fingerprint, String suppressUntil) {
        String sql = """
                INSERT INTO alerts(rule_name, severity, fingerprint, suppress_until) VALUES (:rule_name, :severity, :fingerprint, now() + CAST(:suppress_until AS INTERVAL)) ON CONFLICT (fingerprint) DO UPDATE SET suppress_until = excluded.suppress_until RETURNING id;
""";
       return  jdbc.sql(sql).params(Map.of("rule_name", ruleName, "severity", severity, "fingerprint", fingerprint, "suppress_until", suppressUntil)).query(Long.class).single();

    }


    public List<Alert> findAll(int page, int size) {
        int offset = page*size;
        String sql = "SELECT * FROM alerts ORDER BY created_at DESC LIMIT :limit OFFSET :offset";

        return jdbc.sql(sql).param("limit", size).param("offset", offset).query(Alert.class).list();
    }

    public int acknowledgeAlert(Long alertId) {
        String sql = "UPDATE alerts SET acknowledged_at = NOW() WHERE id = :alertId AND acknowledged_at ISNULL ";

        return jdbc.sql(sql).param("alertId", alertId).update();
    }


}