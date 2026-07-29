package dev.ali.secureapi.repository;

import dev.ali.secureapi.model.RuleMatch;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

@Slf4j
@Repository
public class DetectionRepository {
    private final JdbcClient jdbc;

    public DetectionRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public List<RuleMatch> findIpBruteForce(OffsetDateTime windowStart, OffsetDateTime windowEnd, int threshold) {
        log.info("threshold: {}", threshold);
        String sql = "SELECT host(source_ip) as entity, COUNT(*) as metricValue FROM security_events WHERE event_type = 'AUTH_FAILURE' AND ((created_at >= :window_end) AND (created_at <= :window_start)) GROUP BY source_ip HAVING COUNT(*)  >= :threshold";
         return jdbc.sql(sql).params(Map.of("window_start", Timestamp.from(windowStart.toInstant()), "window_end", Timestamp.from(windowEnd.toInstant()), "threshold", threshold)).query(RuleMatch.class).list();
    };

    public List<RuleMatch> findPasswordSpraying(OffsetDateTime windowStart, OffsetDateTime windowEnd, int threshold) {
        String sql = "SELECT host(source_ip) as entity, COUNT(*) as metricValue FROM security_events WHERE event_type = 'AUTH_FAILURE' AND  created_at <= :windowEnd AND created_at >= :windowStart GROUP BY source_ip HAVING COUNT(DISTINCT principal) >= :threshold ";

        return jdbc.sql(sql).params().query(RuleMatch.class).list();
    }





}
