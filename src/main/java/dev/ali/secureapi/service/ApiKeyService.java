package dev.ali.secureapi.service;

import dev.ali.secureapi.dto.ApiKeyDTO;
import dev.ali.secureapi.dto.CreateApiKeyRequest;
import dev.ali.secureapi.dto.NewApiKeyResponse;
import dev.ali.secureapi.enums.ApiKeysScope;
import dev.ali.secureapi.enums.SecurityEventType;
import dev.ali.secureapi.exception.ApiException;
import dev.ali.secureapi.model.SecurityContextEvent;
import dev.ali.secureapi.repository.ApiKeyRepository;
import dev.ali.secureapi.utils.ApiKeyGenerator;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

@Service
public class ApiKeyService {

    private final ApiKeyRepository apiKeyRepository;
    private final ApiKeyGenerator apiKeyGenerator;
    private final AuthzService authzService;
    private final ApplicationEventPublisher publisher;

    public ApiKeyService(ApiKeyRepository apiKeyRepository, ApiKeyGenerator apiKeyGenerator, AuthzService authzService, ApplicationEventPublisher publisher) {
        this.apiKeyRepository = apiKeyRepository;
        this.apiKeyGenerator = apiKeyGenerator;
        this.authzService = authzService;
        this.publisher = publisher;
    }

    public NewApiKeyResponse createKey(Long ownerId, CreateApiKeyRequest req) throws NoSuchAlgorithmException {

        try {
            ApiKeysScope.parse(req.scopes());
        } catch (NullPointerException | IllegalArgumentException exception) {
            throw new ApiException(400, "Invalid scopes", Map.of());
        }

        String secret = apiKeyGenerator.newSecretKey();
        String hashString = apiKeyGenerator.hash(secret);
        Long id = apiKeyRepository.insert(ownerId, req.label(), secret.substring(0, 12), hashString, req.scopes(), Instant.now().plus(90, ChronoUnit.DAYS));
        ApiKeyDTO apiKeyDTO = new ApiKeyDTO(id, req.label(), secret.substring(0, 12), req.scopes(), Instant.now(), null, Instant.now().plus(90, ChronoUnit.DAYS), null );
        publisher.publishEvent(new SecurityContextEvent(this, SecurityEventType.API_KEY_CREATED, String.valueOf(ownerId), Map.of("keyId", String.valueOf(id), "prefix", apiKeyDTO.keyPrefix(), "scopes", apiKeyDTO.scopes())));

        return new NewApiKeyResponse(apiKeyDTO, secret );
    }

    public List<ApiKeyDTO> listMyKeys(Long ownerId) {
        return apiKeyRepository.findByUserId(ownerId);
    }

    public void revokeKey(Long keyId, Long requesterId, boolean isAdmin) {
        Long ownerId = apiKeyRepository.findOwnerId(keyId);
        authzService.requireOwnerOrAdmin(ownerId, requesterId, isAdmin);
        apiKeyRepository.revokeByIdAndOwner(keyId, ownerId);
        publisher.publishEvent(new SecurityContextEvent(this, SecurityEventType.API_KEY_REVOKED, String.valueOf(requesterId), Map.of("keyId", String.valueOf(keyId))));
    }


}
