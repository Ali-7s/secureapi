package dev.ali.secureapi.config;

import jakarta.validation.Valid;
import org.hibernate.validator.constraints.Length;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "jwt")
@Validated
public record JwtProperties(@Valid SecretPair access, @Valid SecretPair refresh) {
    public record SecretPair(@Length(min = 32) String secret) {}
}