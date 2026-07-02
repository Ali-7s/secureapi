package dev.ali.secureapi.service;

import dev.ali.secureapi.model.SecurityEvent;
import dev.ali.secureapi.repository.SecurityEventRepository;

public class EventService {
    private final SecurityEventRepository securityEventRepository;


    public EventService(SecurityEventRepository securityEventRepository) {
        this.securityEventRepository = securityEventRepository;
    }

    public void save(SecurityEvent securityEvent) {
        securityEventRepository.insert(securityEvent);
    }
}