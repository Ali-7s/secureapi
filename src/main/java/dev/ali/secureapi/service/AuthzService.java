package dev.ali.secureapi.service;

import dev.ali.secureapi.enums.ApiKeysScope;
import dev.ali.secureapi.enums.SecurityEventType;
import dev.ali.secureapi.exception.ApiException;
import dev.ali.secureapi.model.ApiKey;
import dev.ali.secureapi.model.SecurityContextEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

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

    public void requireOwnerOrAdmin(Long requestedId, Long requesterId, boolean isAdmin) {
        if (!isOwner(requestedId, requesterId) && !isAdmin) {
            publisher.publishEvent(new SecurityContextEvent(this, SecurityEventType.AUTHZ_IDOR, String.valueOf(requesterId), Map.of("requestedId", requestedId.toString())));
            throw new ApiException(403, "An error occurred with the requested id", null);
        }
    }

    public void requireScope(String storedScopes, ApiKeysScope required, ApiKey key) {
        if (!ApiKeysScope.parse(storedScopes).contains(required)) {
            publisher.publishEvent(new SecurityContextEvent(this, SecurityEventType.AUTHZ_DENIED, key.id().toString(), Map.of("keyLabel", key.label(), "keyPrefix", key.keyPrefix(), "scopes", key.scopes())));
            throw new ApiException(403, "Invalid scopes", Map.of());

        }
    }

}
