package dev.ali.secureapi.dto;

import jakarta.validation.constraints.NotEmpty;

public record LoginRequest(@NotEmpty(message = "Email cannot be empty.") String email,
                           @NotEmpty(message = "Password cannot be empty.") String password) {
}
