package dev.ali.secureapi.listener;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.ali.secureapi.model.SecurityContextEvent;
import dev.ali.secureapi.model.SecurityEvent;
import dev.ali.secureapi.repository.SecurityEventRepository;
import dev.ali.secureapi.service.DetectionService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.OffsetDateTime;

@Slf4j
@Service
public class SecurityAuditListener {
    private final SecurityEventRepository securityEventRepository;
    private final DetectionService detectionService;
    private final ObjectMapper objectMapper;

    public SecurityAuditListener(SecurityEventRepository securityEventRepository, DetectionService detectionService, ObjectMapper objectMapper) {
        this.securityEventRepository = securityEventRepository;
        this.detectionService = detectionService;
        this.objectMapper = objectMapper;
    }


    @EventListener
    public void handleSecurityEvent(SecurityContextEvent event) throws JsonProcessingException {
        ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        HttpServletRequest request = attrs.getRequest();
        String detailsJson = objectMapper.writeValueAsString(event.getMetadata());
        SecurityEvent securityEvent = new SecurityEvent(event.getType(), event.getPrincipal(), request.getRemoteAddr(), detailsJson);


        switch (event.getType()) {
            case AUTH_SUCCESS:
                securityEventRepository.insert(securityEvent);
                detectionService.findBruteForce(OffsetDateTime.now(), OffsetDateTime.now().minusMinutes(10), 10);
                break;
            case AUTH_FAILURE:
                securityEventRepository.insert(securityEvent);
                detectionService.findBruteForce(OffsetDateTime.now(), OffsetDateTime.now().minusMinutes(10), 10);
                break;
            case AUTH_REPLAY:
                securityEventRepository.insert(securityEvent);
                break;
            case AUTH_LOGOUT:
                securityEventRepository.insert(securityEvent);
                break;

            // authorization
            case AUTHZ_DENIED:
                securityEventRepository.insert(securityEvent);
                break;
            case AUTHZ_IDOR:
                securityEventRepository.insert(securityEvent);
                break;

            // jwt
            case JWT_EXPIRED:
                securityEventRepository.insert(securityEvent);
                break;
            case JWT_TAMPERED:
                securityEventRepository.insert(securityEvent);
                break;
            case JWT_MALFORMED:
                securityEventRepository.insert(securityEvent);
                break;

            // sys
            case RATE_LIMIT_HIT:
                securityEventRepository.insert(securityEvent);
                break;
            case GEO_MISMATCH:
                securityEventRepository.insert(securityEvent);
                break;
            case ACCOUNT_LOCKED:
                securityEventRepository.insert(securityEvent);
                break;
        }

    }


}
