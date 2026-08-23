package dev.ali.secureapi.service;

import dev.ali.secureapi.enums.SecurityEventType;
import dev.ali.secureapi.model.SecurityContextEvent;
import dev.ali.secureapi.repository.AccountLockoutRepository;
import dev.ali.secureapi.repository.SecurityEventRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

@Service

public class LockoutService {
    private final AccountLockoutRepository accountLockoutRepository;
    private final SecurityEventRepository securityEventRepository;
    private final ApplicationEventPublisher publisher;
    private final int threshold;
    private final Duration lockoutWindow;
    private final Duration lockoutDuration;

    public LockoutService(AccountLockoutRepository accountLockoutRepository, SecurityEventRepository securityEventRepository, ApplicationEventPublisher publisher, @Value("${lockout.threshold:10}") int threshold, @Value("${lockout.window:PT15M}") Duration lockoutWindow, @Value("${lockout.duration:PT15M}") Duration lockoutDuration) {
        this.accountLockoutRepository = accountLockoutRepository;
        this.securityEventRepository = securityEventRepository;
        this.publisher = publisher;
        this.threshold = threshold;
        this.lockoutWindow = lockoutWindow;
        this.lockoutDuration = lockoutDuration;
    }

    public boolean isLocked(String principal) {
        Optional<OffsetDateTime> time = accountLockoutRepository.findLockedUntil(principal);
        return time.map(offsetDateTime -> offsetDateTime.isAfter(OffsetDateTime.now())).orElse(false);
    }

    public void recordFailure(String principal) {
        int failures = securityEventRepository.countFailureSinceLastSuccess(principal, OffsetDateTime.now().minus(lockoutWindow));

        if(failures >= threshold) {

            OffsetDateTime lockedUntil  = accountLockoutRepository.upsertLock(principal, lockoutDuration.toString());
            publisher.publishEvent(new SecurityContextEvent(this, SecurityEventType.ACCOUNT_LOCKED, principal, Map.of("lockedUntil", lockedUntil.toString())));
        }

    }
}
