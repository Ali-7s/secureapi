package dev.ali.secureapi.dto;

public record NewApiKeyResponse(ApiKeyDTO apiKeyDTO, String plaintextKey) {
}
