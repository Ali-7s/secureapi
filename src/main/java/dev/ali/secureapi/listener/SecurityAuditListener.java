package dev.ali.secureapi.listener;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.ali.secureapi.model.SecurityContextEvent;
import dev.ali.secureapi.model.SecurityEvent;
import dev.ali.secureapi.repository.SecurityEventRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Slf4j
@Service
public class SecurityAuditListener {
    private final SecurityEventRepository securityEventRepository;
    private final ObjectMapper objectMapper;

    public SecurityAuditListener(SecurityEventRepository securityEventRepository, ObjectMapper objectMapper) {
        this.securityEventRepository = securityEventRepository;
        this.objectMapper = objectMapper;
    }

    @EventListener
    public void handleSecurityEvent(SecurityContextEvent event) throws JsonProcessingException {
        ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        HttpServletRequest request = attrs.getRequest();
        String detailsJson = objectMapper.writeValueAsString(event.getMetadata());
        log.info("Before creating event in handleSecurityEvent");
        SecurityEvent securityEvent = new SecurityEvent(event.getType(), event.getPrincipal(), request.getRemoteAddr(), detailsJson);
        securityEventRepository.insert(securityEvent);

    }

}
