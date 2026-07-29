package dev.ali.secureapi.controller;

import dev.ali.secureapi.dto.ApiKeyDTO;
import dev.ali.secureapi.dto.CreateApiKeyRequest;
import dev.ali.secureapi.dto.NewApiKeyResponse;
import dev.ali.secureapi.model.ApiResponse;
import dev.ali.secureapi.service.ApiKeyService;
import dev.ali.secureapi.utils.SecurityUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;
import java.util.List;

import static dev.ali.secureapi.model.ApiResponse.success;

@RestController
@RequestMapping("/api/keys")
public class ApiKeyController {

    private final ApiKeyService apiKeyService;

    public ApiKeyController(ApiKeyService apiKeyService) {
        this.apiKeyService = apiKeyService;
    }


    @PostMapping("")
    public ResponseEntity<ApiResponse<NewApiKeyResponse>> createKey(Authentication auth, @RequestBody CreateApiKeyRequest req) throws NoSuchAlgorithmException {
        Long ownerId = SecurityUtils.getCurrentUser(auth).getId();
        NewApiKeyResponse key = apiKeyService.createKey(ownerId, req);
        // return 201
        return ResponseEntity.status(HttpStatus.CREATED).body(success("Key created", key));
    };

    @GetMapping("")
    public ResponseEntity<ApiResponse<List<ApiKeyDTO>>> listMyKeys(Authentication auth) {
        Long ownerId = SecurityUtils.getCurrentUser(auth).getId();
        return ResponseEntity.status(HttpStatus.OK).body(success("Keys returned", apiKeyService.listMyKeys(ownerId)));

    }


    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> revokeKey(@PathVariable Long id, Authentication auth) {
        Long ownerId = SecurityUtils.getCurrentUser(auth).getId();
        boolean isAdmin = SecurityUtils.isAdmin(auth);
        apiKeyService.revokeKey(id, ownerId, isAdmin);
        return ResponseEntity.status(HttpStatus.OK).body(success("Key revoked", null));
    }


}
