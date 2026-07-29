package dev.ali.secureapi.service;

import dev.ali.secureapi.enums.ApiKeysScope;
import dev.ali.secureapi.enums.SecurityEventType;
import dev.ali.secureapi.exception.ApiException;
import dev.ali.secureapi.model.ApiKey;
import dev.ali.secureapi.model.SecurityContextEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.util.Map;

@Service
public class AuthzService {

    private final ApplicationEventPublisher publisher;

    public AuthzService(ApplicationEventPublisher eventPublisher) {
        this.publisher = eventPublisher;
    }

    public boolean isOwner(Long resourceOwnerId, Long requesterId) {
        return resourceOwnerId.equals(requesterId);
    }

    public void requireOwnerOrAdmin(Long resourceOwnerId, Long requesterId, boolean isAdmin) {
        if(!isOwner(resourceOwnerId, requesterId) &&  !isAdmin) {
            publisher.publishEvent(new SecurityContextEvent(this, SecurityEventType.AUTHZ_IDOR, String.valueOf(requesterId), Map.of("resourceOwnerId", String.valueOf(resourceOwnerId))));
            throw new ApiException(403, "Security violation: AUTHZ_IDOR", null);
        }
    }

    public void requireScope(String storedScopes, ApiKeysScope required, ApiKey key) {
        if(!ApiKeysScope.parse(storedScopes).contains(required))  {
            publisher.publishEvent(new SecurityContextEvent(this, SecurityEventType.AUTHZ_DENIED, key.id().toString(), Map.of("keyLabel", key.label(),"keyPrefix", key.keyPrefix(), "scopes", key.scopes())));
            throw new ApiException(403, "Invalid scopes", Map.of());

        }
    }

}
