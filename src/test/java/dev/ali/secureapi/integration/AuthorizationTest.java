package dev.ali.secureapi.integration;

import dev.ali.secureapi.AbstractIntegrationTest;
import dev.ali.secureapi.dto.CreateApiKeyRequest;
import dev.ali.secureapi.dto.NewApiKeyResponse;
import dev.ali.secureapi.dto.RegisterRequest;
import dev.ali.secureapi.service.AlertService;
import dev.ali.secureapi.service.ApiKeyService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithUserDetails;
import dev.ali.secureapi.dto.*;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

public class AuthorizationTest extends AbstractIntegrationTest {

    private Integer firstId;
    private Integer secondId;
    private Long alertId;
    @Autowired
    private ApiKeyService apiKeyService;

    @BeforeEach
    void seed() throws Exception {
        jdbcClient.sql("truncate users, api_keys, security_events, alerts cascade").update();

        RegisterRequest registerReq = new RegisterRequest("test_1@example.test", "TESTING_1", "TEST USER1", "Testing12345");
        RegisterRequest secondRegisterReq = new RegisterRequest("test_2@example.test", "TESTING_2", "TEST USER2", "Hamburger12345");
        RegisterRequest thirdRegisterReq = new RegisterRequest("test_admin@example.test", "TESTING_ADMIN", "TEST ADMIN", "Administrator12345");
        firstId = createOne(registerReq);
        secondId = createOne(secondRegisterReq);
        Integer thirdId = createOne(thirdRegisterReq);
        jdbcClient.sql("UPDATE users SET role = 'ADMIN' WHERE id = :id").param("id", thirdId).update();
        alertId = jdbcClient.sql("""
        insert into alerts (rule_name, severity, fingerprint, suppress_until)
        values ('BRUTE_FORCE', 'MEDIUM', 'AUTHZ:test', now() + interval '1 hour')
        returning id
        """)
                .query(Long.class)
                .single();

    }

    @Test
    @WithUserDetails(value = "test_1@example.test",
            setupBefore = TestExecutionEvent.TEST_EXECUTION)
    void rejectsReadingAnotherUsersProfile() throws Exception {
        mockMvc.perform(get("/api/users/{id}", secondId)).andExpect(status().isForbidden());
        Long count = jdbcClient.sql("SELECT COUNT(*) FROM security_events WHERE event_type = 'AUTHZ_IDOR' AND principal = :principal AND details ->> 'requestedId' like :requestedId")
                .params(Map.of("principal", String.valueOf(firstId), "requestedId", String.valueOf(secondId)))
                .query(Long.class)
                .single();
        assertThat(count).isEqualTo(1);
    }


    @Test
    @WithUserDetails(value = "test_1@example.test",
            setupBefore = TestExecutionEvent.TEST_EXECUTION)
    void rejectsRevokingAnotherUsersKey() throws Exception {
        NewApiKeyResponse key = apiKeyService.createKey(Long.valueOf(secondId), new CreateApiKeyRequest("Testing key", "ALERTS_READ,ALERTS_WRITE" ) );
        mockMvc.perform(delete("/api/keys/{id}", key.apiKeyDTO().id()).with(csrf()).contentType(MediaType.APPLICATION_JSON)).andExpect(status().isForbidden());
        Optional<Instant> revokedAt = jdbcClient.sql("SELECT revoked_at FROM api_keys WHERE id = :id").param("id", key.apiKeyDTO().id()).query(Instant.class).optional();
        assertThat(revokedAt.isEmpty()).isTrue();
    }

    @Test
    void allowsAdminToRevokeAnyKey() throws Exception {
        LoginRequest loginRequest = new LoginRequest("test_admin@example.test", "Administrator12345");
        NewApiKeyResponse key = apiKeyService.createKey(Long.valueOf(secondId), new CreateApiKeyRequest("Testing key", "ALERTS_READ,ALERTS_WRITE" ) );

        MvcResult login = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(loginRequest))).andExpect(status().isOk())
                .andReturn();

        Cookie[] cookies = login.getResponse().getCookies();
        mockMvc.perform(delete("/api/keys/{id}", key.apiKeyDTO().id()).with(csrf()).cookie(cookies)).andExpect(status().isOk());
        Optional<Instant> revokedAt = jdbcClient.sql("SELECT revoked_at FROM api_keys WHERE id = :id").param("id", key.apiKeyDTO().id()).query(Instant.class).optional();

        assertThat(revokedAt.isPresent()).isTrue();
    }

    @Test
    void rejectsAcknowledgeWithReadOnlyKey() throws Exception {
        NewApiKeyResponse key = apiKeyService.createKey(Long.valueOf(secondId), new CreateApiKeyRequest("Testing key", "ALERTS_READ" ) );

        mockMvc.perform(post("/api/alerts/{id}/acknowledge", alertId).header("X-API-Key", key.plaintextKey())).andExpect(status().isForbidden());
        Long count = jdbcClient.sql("SELECT COUNT(*) FROM security_events WHERE event_type = 'AUTHZ_DENIED' AND jsonb_exists(details, 'scopes') ")
                .query(Long.class)
                .single();
        assertThat(count).isEqualTo(1);
        Optional<Instant> acknowledgedAt = jdbcClient.sql("SELECT acknowledged_at from alerts where id = :id").param("id", alertId).query(Instant.class).optional();
        assertThat(acknowledgedAt.isEmpty()).isTrue();
    }

    @Test
    void allowsAcknowledgeWithWriteScopedKey() throws Exception {
        NewApiKeyResponse key = apiKeyService.createKey(Long.valueOf(secondId), new CreateApiKeyRequest("Testing key", "ALERTS_READ,ALERTS_WRITE" ) );
        mockMvc.perform(post("/api/alerts/{id}/acknowledge", alertId).header("X-API-Key", key.plaintextKey())).andExpect(status().isOk());
        Optional<Instant> acknowledgedAt = jdbcClient.sql("SELECT acknowledged_at from alerts where id = :id").param("id", alertId).query(Instant.class).optional();
        assertThat(acknowledgedAt.isPresent()).isTrue();

    }


}
