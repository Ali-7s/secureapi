package dev.ali.secureapi.service;

import dev.ali.secureapi.model.RuleMatch;
import dev.ali.secureapi.repository.AlertRepository;
import dev.ali.secureapi.repository.DetectionRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.util.List;

@Slf4j
@Service
public class DetectionService {
    private final DetectionRepository detectionRepository;
    private final AlertRepository alertRepository;

    public DetectionService(DetectionRepository detectionRepository, AlertRepository alertRepository) {
        this.detectionRepository = detectionRepository;
        this.alertRepository = alertRepository;
    }

    public void findBruteForce(OffsetDateTime windowStart, OffsetDateTime windowEnd, int threshold) {
        List<RuleMatch> matches = detectionRepository.findIpBruteForce(windowStart, windowEnd, threshold);
        if(!matches.isEmpty()){
            RuleMatch match = matches.get(0);
            log.info("Brute Force detected");
            String fingerprint = "BRUTE_FORCE" + ":" + match.entity();

        }
    }



}