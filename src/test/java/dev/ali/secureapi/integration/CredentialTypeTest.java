package dev.ali.secureapi.integration;

import dev.ali.secureapi.AbstractIntegrationTest;
import dev.ali.secureapi.dto.*;
import dev.ali.secureapi.service.ApiKeyService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class CredentialTypeTest extends AbstractIntegrationTest {

    private Integer firstId;
    @Autowired
    private ApiKeyService apiKeyService;


    @BeforeEach
    void seed() throws Exception {
        jdbcClient.sql("truncate users, security_events, api_keys cascade").update();

        RegisterRequest registerReq = new RegisterRequest("test_1@example.test", "TESTING_1", "TEST USER1", "Testing12345");
        firstId = createOne(registerReq);

    }


    @Test
    void acceptsCookieSessionOnKeyManagement() throws Exception {
        LoginRequest loginRequest = new LoginRequest("test_1@example.test", "Testing12345");

        MvcResult login = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(loginRequest))).andExpect(status().isOk())
                .andReturn();

        Cookie[] cookies = login.getResponse().getCookies();
        mockMvc.perform(get("/api/keys").with(csrf()).cookie(cookies)).andExpect(status().isOk());

    }

    @Test
    void rejectsApiKeyOnKeyManagement() throws Exception {
        NewApiKeyResponse key = apiKeyService.createKey(Long.valueOf(firstId), new CreateApiKeyRequest("Testing key", "ALERTS_READ,ALERTS_WRITE" ) );
        mockMvc.perform(get("/api/keys").header("X-API-Key", key.plaintextKey())).andExpect(status().isForbidden());
        Long count = jdbcClient.sql("SELECT COUNT(*) FROM security_events WHERE event_type = 'AUTHZ_DENIED' AND details ->> 'path' like :path")
                .param("path", "/api/keys%")
                .query(Long.class)
                .single();

        assertThat(count).isEqualTo(1);
    }

    @Test
    void acceptsApiKeyOnAlertFeed() throws Exception {
        NewApiKeyResponse key = apiKeyService.createKey(Long.valueOf(firstId), new CreateApiKeyRequest("Testing key", "ALERTS_READ,ALERTS_WRITE" ) );
        mockMvc.perform(get("/api/alerts").header("X-API-Key", key.plaintextKey())).andExpect(status().isOk());
    }

    @Test
    void rejectsApiKeyAlongsideValidSession() throws Exception {
        NewApiKeyResponse key = apiKeyService.createKey(Long.valueOf(firstId), new CreateApiKeyRequest("Testing key", "ALERTS_READ,ALERTS_WRITE" ) );
        LoginRequest loginRequest = new LoginRequest("test_1@example.test", "Testing12345");

        MvcResult login = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(loginRequest))).andExpect(status().isOk())
                .andReturn();
        Cookie[] cookies = login.getResponse().getCookies();
        CreateApiKeyRequest request = new CreateApiKeyRequest("Testing key", "ALERTS_READ,ALERTS_WRITE" );
        mockMvc.perform(post("/api/keys").contentType(MediaType.APPLICATION_JSON).with(csrf()).cookie(cookies).header("X-API-Key", key.plaintextKey()).content(objectMapper.writeValueAsString(request))).andExpect(status().isForbidden());

        Long count = jdbcClient.sql("SELECT COUNT(*) FROM api_keys")
                .query(Long.class)
                .single();

        assertThat(count).isEqualTo(1);

    }

    @Test
    void rejectsCookieSessionOnAlerts() throws Exception {
        LoginRequest loginRequest = new LoginRequest("test_1@example.test", "Testing12345");

        MvcResult login = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(loginRequest))).andExpect(status().isOk())
                .andReturn();

        Cookie[] cookies = login.getResponse().getCookies();
        mockMvc.perform(get("/api/alerts").cookie(cookies)).andExpect(status().isForbidden());

    }



}
