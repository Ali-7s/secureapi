package dev.ali.secureapi.detection.rules;

import dev.ali.secureapi.detection.DetectionRule;
import dev.ali.secureapi.enums.AttackPatternType;
import dev.ali.secureapi.enums.SecurityEventType;
import dev.ali.secureapi.enums.Severity;
import dev.ali.secureapi.model.RuleMatch;
import dev.ali.secureapi.repository.DetectionRepository;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;


@Component
public class TokenReplayRule implements DetectionRule {

    private final DetectionRepository detectionRepository;

    public TokenReplayRule(DetectionRepository detectionRepository) {
        this.detectionRepository = detectionRepository;
    }

    @Override
    public AttackPatternType name() {
        return AttackPatternType.TOKEN_REPLAY;
    }

    @Override
    public Severity severity() {
        return Severity.CRITICAL;
    }

    @Override
    public Duration window() {
        return Duration.ofMinutes(10);
    }

    @Override
    public int threshold() {
        return 10;
    }

    @Override
    public List<RuleMatch> evaluate(OffsetDateTime now) {
        OffsetDateTime windowStart = now.minus(window());
        return detectionRepository.countEventsBySourceIp(SecurityEventType.AUTH_REPLAY, windowStart, now, threshold());
    }

    @Override
    public Duration suppressFor() {
        return Duration.ofMinutes(5);
    }
}
