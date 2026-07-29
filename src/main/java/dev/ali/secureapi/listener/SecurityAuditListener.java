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
        securityEventRepository.insert(securityEvent);

        switch (event.getType()) {
            case AUTH_FAILURE:
                break;
            case AUTH_REPLAY:
                break;

            // authorization
            case AUTHZ_DENIED:
                break;
            case AUTHZ_IDOR:
                break;

            // jwt
            case JWT_EXPIRED:
                break;
            case JWT_TAMPERED:
                break;
            case JWT_MALFORMED:
                break;
            // sys
            case RATE_LIMIT_HIT:
                break;
        }

    }


}
