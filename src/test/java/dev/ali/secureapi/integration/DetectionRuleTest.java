package dev.ali.secureapi.integration;

import dev.ali.secureapi.AbstractIntegrationTest;
import dev.ali.secureapi.detection.rules.BruteForceRule;
import dev.ali.secureapi.detection.rules.KeyIdorRule;
import dev.ali.secureapi.detection.rules.PasswordSprayingRule;
import dev.ali.secureapi.detection.rules.TokenReplayRule;
import dev.ali.secureapi.enums.SecurityEventType;
import dev.ali.secureapi.model.RuleMatch;
import dev.ali.secureapi.service.DetectionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(properties = "detection.scan-interval-ms=3600000")
class DetectionRuleTest extends AbstractIntegrationTest {

    private final OffsetDateTime now = OffsetDateTime.now();
    @Autowired
    private DetectionService detectionService;
    @Autowired
    private BruteForceRule bruteForceRule;
    @Autowired
    private PasswordSprayingRule passwordSprayingRule;
    @Autowired
    private KeyIdorRule keyIdorRule;
    @Autowired
    private TokenReplayRule tokenReplayRule;


    @BeforeEach
    void clear() {
        jdbcClient.sql("truncate security_events, alerts").update();
    }

    private void seed(String type, String principal, String ip, OffsetDateTime at) {
        jdbcClient.sql("""
                        insert into security_events (event_type, principal, source_ip, created_at)
                        values (:type, :principal, cast(:ip as inet), :at)
                        """)
                .param("type", type)
                .param("principal", principal)
                .param("ip", ip)
                .param("at", Timestamp.from(at.toInstant()))
                .update();
    }

    private void seedEvents(int count, String type, String principal, String ip, OffsetDateTime at) {
        for (int i = 0; i < count; i++) seed(type, principal, ip, at);
    }

    private void seedSpray(int count, String ip, OffsetDateTime at) {
        for (int i = 0; i < count; i++) seed("AUTH_FAILURE", "user" + i + "@example.test", ip, at);
    }


    @Test
    void firesAtThreshold() {
        seedSpray(10, "10.1.3.2", now);
        List<RuleMatch> ruleMatches = passwordSprayingRule.evaluate(now);
        assertThat(ruleMatches.get(0).entity()).isEqualTo("10.1.3.2");
        assertThat(ruleMatches.get(0).count()).isEqualTo(10);
    }

    @Test
    void doesNotFireBelowThreshold() {
        seedSpray(9, "10.1.3.2", now);
        List<RuleMatch> ruleMatches = passwordSprayingRule.evaluate(now);
        assertThat(ruleMatches.isEmpty()).isTrue();
    }

    @Test
    void ignoresEventsOutsideTheWindow() {
        seedSpray(10, "10.1.3.2", now.minusMinutes(11));
        List<RuleMatch> ruleMatches = passwordSprayingRule.evaluate(now);
        assertThat(ruleMatches.isEmpty()).isTrue();
    }

    @Test
    void distinguishesSprayingFromBruteForce() {
        seedSpray(10, "10.1.3.2", now);
        List<RuleMatch> passSpray1 = passwordSprayingRule.evaluate(now);
        List<RuleMatch> bruteForce1 = bruteForceRule.evaluate(now);
        assertThat(passSpray1.isEmpty()).isFalse();
        assertThat(bruteForce1.isEmpty()).isFalse();
        clear();
        seedEvents(10, "AUTH_FAILURE", "user@example.test", "10.2.3.1", now);
        List<RuleMatch> passSpray2 = passwordSprayingRule.evaluate(now);
        List<RuleMatch> bruteForce2 = bruteForceRule.evaluate(now);
        assertThat(passSpray2.isEmpty()).isTrue();
        assertThat(bruteForce2.isEmpty()).isFalse();
    }

    @Test
    void suppressesRepeatScanWithinBucket() {
        seedSpray(10, "10.1.3.2", now);
        detectionService.runRule(passwordSprayingRule, now);
        Instant suppressUntil = jdbcClient.sql("select suppress_until from alerts")
                .query(Instant.class)
                .single();
        detectionService.runRule(passwordSprayingRule, now);
         Instant suppressUntil2 = jdbcClient.sql("select suppress_until from alerts")
                .query(Instant.class)
                .single();

         assertThat(suppressUntil.isBefore(suppressUntil2)).isTrue();
    }

    @Test
    void raisesNewAlertAfterAcknowledgement() {
        seedSpray(10, "10.1.3.2", now);
        detectionService.runRule(passwordSprayingRule, now);
        jdbcClient.sql("UPDATE alerts SET acknowledged_at = now() WHERE rule_name = 'PASSWORD_SPRAY' AND severity = 'HIGH'").update();
        detectionService.runRule(passwordSprayingRule, now);
        Long count = jdbcClient.sql( "SELECT count(*) from alerts WHERE rule_name = 'PASSWORD_SPRAY' AND severity = 'HIGH'").query(Long.class).single();
        assertThat(count).isEqualTo(2);
    }

    @Test
    void runAllRunsEveryRule() {
        seedSpray(10, "10.1.3.2", now);
        detectionService.runAll(now);
        Long passwordSprayCount = jdbcClient.sql( "SELECT count(*) from alerts WHERE rule_name = 'PASSWORD_SPRAY'").query(Long.class).single();
        Long bruteForceCount = jdbcClient.sql( "SELECT count(*) from alerts WHERE rule_name = 'BRUTE_FORCE'").query(Long.class).single();

        assertThat(passwordSprayCount).isEqualTo(1);
        assertThat(bruteForceCount).isEqualTo(1);
    }

    @Test
    void groupsKeyIdorByPrincipal() {
        seedEvents(5, SecurityEventType.AUTHZ_IDOR.name(), "bill@example.test", "10.2.3.1", now);
        seedEvents(5, SecurityEventType.AUTHZ_IDOR.name(), "john@example.test", "10.2.3.1", now);
        List<RuleMatch> ruleMatches = keyIdorRule.evaluate(now);
        assertThat(ruleMatches.isEmpty()).isTrue();
        clear();
        seedEvents(10, SecurityEventType.AUTHZ_IDOR.name(), "john@example.test", "10.2.3.1", now);
        List<RuleMatch> ruleMatches2 = keyIdorRule.evaluate(now);
        assertThat(ruleMatches2.isEmpty()).isFalse();
        assertThat(ruleMatches2.get(0).entity()).isEqualTo("john@example.test");
    }

    @Test
    void firesOnItsOwnEventTypeOnly() {
        seedEvents(10, SecurityEventType.AUTH_REPLAY.name(), "bill@example.test", "10.2.3.1", now);
        List<RuleMatch> ruleMatches = tokenReplayRule.evaluate(now);
        assertThat(ruleMatches.isEmpty()).isFalse();
        clear();
        seedEvents(10, SecurityEventType.API_KEY_REJECTED.name(), "bill@example.test", "10.2.3.1", now);
        List<RuleMatch> ruleMatches2 = tokenReplayRule.evaluate(now);
        assertThat(ruleMatches2.isEmpty()).isTrue();


    }
}
