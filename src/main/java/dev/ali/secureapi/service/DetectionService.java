package dev.ali.secureapi.service;

import dev.ali.secureapi.detection.DetectionRule;
import dev.ali.secureapi.model.RuleMatch;
import dev.ali.secureapi.repository.AlertRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.List;

@Slf4j
@Service
public class DetectionService {
    private final List<DetectionRule> detectionRules;
    private final AlertRepository alertRepository;

    public DetectionService(List<DetectionRule> detectionRules, AlertRepository alertRepository) {
        this.detectionRules = detectionRules;
        this.alertRepository = alertRepository;
    }


    public void runRule(DetectionRule rule, OffsetDateTime now) {
        long bucketNumber = now.toEpochSecond() / rule.suppressFor().toSeconds();
        long bucketStartSeconds = rule.suppressFor().toSeconds() * bucketNumber;
        Instant timeBucket = Instant.ofEpochSecond(bucketStartSeconds);


        List<RuleMatch> matches = rule.evaluate(now);
        matches.forEach(m -> {
            String fingerprint = rule.name() + ":" + m.entity() + ":" + timeBucket;
            alertRepository.insert(rule.name().name(), rule.severity().name(), fingerprint, rule.suppressFor().toString());
        });
    }

    public void runAll(OffsetDateTime now) {
        detectionRules.forEach(r -> {
            try {
                runRule(r, now);
            } catch (Exception e) {
                log.error("Rule name - {} failed", r.name(), e);
            }
        });

    }


}