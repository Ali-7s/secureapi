package dev.ali.secureapi.detection;

import dev.ali.secureapi.enums.AttackPatternType;
import dev.ali.secureapi.enums.Severity;
import dev.ali.secureapi.model.RuleMatch;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;

public interface DetectionRule {
    AttackPatternType name();

    Severity severity();

    Duration window();

    int threshold();

    List<RuleMatch> evaluate(OffsetDateTime now);

    Duration suppressFor();

}
