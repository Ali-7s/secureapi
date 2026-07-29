package dev.ali.secureapi.service;

import dev.ali.secureapi.enums.ApiKeysScope;
import dev.ali.secureapi.exception.ApiException;
import dev.ali.secureapi.model.Alert;
import dev.ali.secureapi.model.ApiKey;
import dev.ali.secureapi.repository.AlertRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AlertService {
    private final AlertRepository alertRepository;
    private final AuthzService authzService;

    public AlertService(AlertRepository alertRepository, AuthzService authzService) {
        this.alertRepository = alertRepository;
        this.authzService = authzService;
    }


    public List<Alert> listAlerts(String keyScopes, int page, int size, ApiKey principal) {
        authzService.requireScope(keyScopes, ApiKeysScope.ALERTS_READ, principal);
        size = Math.min(size, 100);
        return alertRepository.findAll(page, size);

    }

    public void acknowledgeAlert(String keyScopes, Long alertId, ApiKey key) {
        authzService.requireScope(keyScopes, ApiKeysScope.ALERTS_WRITE, key );
        int returnedInt = alertRepository.acknowledgeAlert(alertId);
        if(returnedInt < 1) {
            throw new ApiException(404, "Acknowledgement failed", null);
        }


    }



}
