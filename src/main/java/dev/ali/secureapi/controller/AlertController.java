package dev.ali.secureapi.controller;

import dev.ali.secureapi.exception.ApiException;
import dev.ali.secureapi.model.Alert;
import dev.ali.secureapi.model.ApiKey;
import dev.ali.secureapi.model.ApiResponse;
import dev.ali.secureapi.service.AlertService;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

import static dev.ali.secureapi.model.ApiResponse.success;

@RestController
@RequestMapping("/api/alerts")
@SecurityRequirement(name = "X-API-Key")
public class AlertController {

    private final AlertService alertService;


    public AlertController(AlertService alertService) {
        this.alertService = alertService;
    }

    @GetMapping("")
    public List<Alert> getAlerts(Authentication auth, @RequestParam(defaultValue = "0") int page,
                                 @RequestParam(defaultValue = "100") int size) {
        if (!(auth.getPrincipal() instanceof ApiKey key)) {

            throw new ApiException(403, "Authorization Denied", null);
        }

        return alertService.listAlerts(key.scopes(), page, size, key);
    }


    @PostMapping("/{id}/acknowledge")
    public ResponseEntity<ApiResponse<Void>> acknowledge(@PathVariable Long id, Authentication auth) {
        if (!(auth.getPrincipal() instanceof ApiKey key)) {

            throw new ApiException(403, "Authorization Denied", null);
        }

        alertService.acknowledgeAlert(key.scopes(), id, key);

        return ResponseEntity.status(HttpStatus.OK).body(success("Alert acknowledge", null));

    }
}


