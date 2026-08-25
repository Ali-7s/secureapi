package dev.ali.secureapi.dto;

import jakarta.validation.constraints.*;

public record RegisterRequest(
        @NotEmpty(message = "Email cannot be null")
        @Email(message = "Please enter a valid email address")
        String email,
        @Pattern(regexp = "^[A-Za-z0-9_]{1,15}$", message = "Invalid username. Please use only letters (a-z), numbers, and underscores.")
        String username,
        @NotEmpty(message = "Display name cannot be null")
        @Size(min = 1, max = 55, message = "Display name must be between 1-55 characters")
        String displayName,
        @NotNull(message = "Password cannot be null")
        @Size(min = 12, message = "Password length must be 12 characters or more")
        String password) {
}