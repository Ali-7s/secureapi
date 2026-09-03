package dev.ali.secureapi.integration;

import dev.ali.secureapi.AbstractIntegrationTest;
import dev.ali.secureapi.dto.RegisterRequest;
import dev.ali.secureapi.dto.UpdateUserProfileRequest;
import dev.ali.secureapi.dto.UserSummaryDTO;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithUserDetails;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class ProfileUpdateTest extends AbstractIntegrationTest {

    private Integer firstId;
    private Integer secondId;

    @BeforeEach
    void seed() throws Exception {
        jdbcClient.sql("truncate users cascade").update();

        RegisterRequest registerReq = new RegisterRequest("test_1@example.test", "TESTING_1", "TEST USER1", "Testing12345");
        RegisterRequest secondRegisterReq = new RegisterRequest("test_2@example.test", "TESTING_2", "TEST USER2", "Hamburger12345");
        firstId = createOne(registerReq);
        secondId = createOne(secondRegisterReq);
    }



    @Test
    @WithUserDetails(value = "test_1@example.test",
            setupBefore = TestExecutionEvent.TEST_EXECUTION)
    public void rejectsUpdateOfAnotherUsersProfile() throws Exception {
        UpdateUserProfileRequest profileRequest = new UpdateUserProfileRequest("IGotAttacked", "AttackedMan");

        mockMvc.perform(put("/api/users/{id}", secondId).with(csrf()).contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(profileRequest))).andExpect(status().isForbidden());


        Long count = jdbcClient.sql("SELECT COUNT(*) FROM security_events WHERE event_type = 'AUTHZ_IDOR' AND principal = :id")
                .param("id", String.valueOf(firstId))
                .query(Long.class)
                .single();

        UserSummaryDTO user = jdbcClient.sql("SELECT username, display_name FROM users WHERE id = :id")
                .param("id", secondId)
                .query(UserSummaryDTO.class)
                .single();

        assertThat(count).isEqualTo(1);
        assertThat(user.getUsername()).isEqualTo("TESTING_2");
        assertThat(user.getDisplayName()).isEqualTo("TEST USER2");
    }

}
