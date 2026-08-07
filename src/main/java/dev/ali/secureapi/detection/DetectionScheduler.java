package dev.ali.secureapi.detection;

import dev.ali.secureapi.service.DetectionService;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;

@Service
@EnableScheduling
public class DetectionScheduler {
    private final DetectionService detectionService;

    public DetectionScheduler(DetectionService detectionService) {
        this.detectionService = detectionService;
    }


    @Scheduled(fixedDelayString = "${detection.scan-interval-ms:30000}")
    public void scan() {
        detectionService.runAll(OffsetDateTime.now());
    }
}
