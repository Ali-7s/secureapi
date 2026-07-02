package dev.ali.secureapi.model;

import dev.ali.secureapi.enums.SecurityEventType;

import java.time.Instant;


public record SecurityEvent(SecurityEventType type, String principal, String ip, String details, Instant timestamp) {
    public SecurityEvent(SecurityEventType type, String principal, String ip, String details) {
        this(type, principal, ip, details, Instant.now());
    }
}
