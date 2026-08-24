package dev.ali.secureapi.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfiguration {

    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
                .components(new Components().addSecuritySchemes("access_token", createSessionJWTScheme()).addSecuritySchemes("X-API-Key", createAPIKeyScheme()))
                .info(new Info().title("SecureAPI")
                        .description("""
                                Users register, authenticate with short-lived JWTs in HttpOnly cookies, and
                                manage scoped API keys. Every authentication and authorization outcome,\s
                                successes, denials, ownership violations, rejected keys is written to an
                                append-only audit trail, which a scheduled detection engine sweeps to raise
                                deduplicated alerts for brute force, password spraying, key enumeration and
                                token replay.
                                
                                Two credential types, deliberately not interchangeable: session cookies for
                                user-owned resources, and an X-API-Key header for the alert feed. A key sent
                                to /api/keys is rejected, as is a cookie session sent to /api/alerts.
                                
                                Write operations require the XSRF-TOKEN cookie echoed back as an X-XSRF-TOKEN
                                header, which this UI does not send, use the scripts in http/ to exercise them.""")
                        .version("1.0").contact(new Contact().name("Ali Sharif").url("https://github.com/Ali-7s")));
    }


    private SecurityScheme createSessionJWTScheme() {
        return new SecurityScheme().type(SecurityScheme.Type.APIKEY).in(SecurityScheme.In.COOKIE).name("access_token");
    }

    private SecurityScheme createAPIKeyScheme() {
        return new SecurityScheme().type(SecurityScheme.Type.APIKEY).in(SecurityScheme.In.HEADER).name("X-API-Key");
    }

}