package dev.ali.secureapi.dto;

import jakarta.validation.constraints.Size;

public record CreateApiKeyRequest(@Size(min = 1, max = 255)String label, String scopes) {
}
