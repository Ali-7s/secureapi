package dev.ali.secureapi.dto;

import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record UpdateUserProfileRequest(
        @Pattern(regexp = "^[A-Za-z0-9_]{1,15}$", message = "Username cannot be empty")
        String username,
        @Size(min = 1, max = 55)
        String displayName
) {
}