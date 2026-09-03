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
        RegisterRequest thirdRegisterReq = new RegisterRequest("test_admin@example.test", "TESTING_ADMIN", "TEST ADMIN", "Administrator12345");
        firstId = createOne(registerReq);
        secondId = createOne(secondRegisterReq);
        Integer thirdId = createOne(thirdRegisterReq);
        jdbcClient.sql("UPDATE users SET role = 'ADMIN' WHERE id = :id").param("id", thirdId).update();
    }



    @Test
    @WithUserDetails(value = "test_1@example.test",
            setupBefore = TestExecutionEvent.TEST_EXECUTION)
    public void rejectsUpdateOfAnotherUsersProfile() throws Exception {
        UpdateUserProfileRequest profileRequest = new UpdateUserProfileRequest("IGotAttacked", "AttackedMan");

        mockMvc.perform(put("/api/users/{id}", secondId)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(profileRequest)))
                .andExpect(status().isForbidden());


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


    @Test
    @WithUserDetails(value = "test_1@example.test",
            setupBefore = TestExecutionEvent.TEST_EXECUTION)
    public void rejectsUpdateWithoutCsrfToken() throws Exception {
        UpdateUserProfileRequest profileRequest = new UpdateUserProfileRequest("IUpdated", "UpdatedMan");

        mockMvc.perform(put("/api/users/{id}", firstId)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(profileRequest)))
                .andExpect(status().isForbidden());

        UserSummaryDTO user = jdbcClient.sql("SELECT username, display_name FROM users WHERE id = :id")
                .param("id", firstId)
                .query(UserSummaryDTO.class)
                .single();

        assertThat(user.getUsername()).isEqualTo("TESTING_1");
        assertThat(user.getDisplayName()).isEqualTo("TEST USER1");
    }

    @Test
    @WithUserDetails(value = "test_1@example.test",
            setupBefore = TestExecutionEvent.TEST_EXECUTION)
    public void updatesOwnProfile() throws Exception {
        UpdateUserProfileRequest profileRequest = new UpdateUserProfileRequest("IUpdated", "UpdatedMan");
        mockMvc.perform(put("/api/users/{id}", firstId)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(profileRequest)))
                .andExpect(status().isOk());
        UserSummaryDTO user = jdbcClient.sql("SELECT username, display_name FROM users WHERE id = :id")
                .param("id", firstId)
                .query(UserSummaryDTO.class)
                .single();

        assertThat(user.getUsername()).isEqualTo("IUpdated");
        assertThat(user.getDisplayName()).isEqualTo("UpdatedMan");
    }

    @Test
    @WithUserDetails(value = "test_1@example.test",
            setupBefore = TestExecutionEvent.TEST_EXECUTION)
    public void leavesOmittedFieldsUnchanged() throws Exception {
        mockMvc.perform(put("/api/users/{id}", firstId)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"displayName\":  \"ChangedMan\" }"))
                .andExpect(status().isOk());
        UserSummaryDTO user = jdbcClient.sql("SELECT username, display_name FROM users WHERE id = :id")
                .param("id", firstId)
                .query(UserSummaryDTO.class)
                .single();

        assertThat(user.getUsername()).isEqualTo("TESTING_1");
        assertThat(user.getDisplayName()).isEqualTo("ChangedMan");
    }


    @Test
    @WithUserDetails(value = "test_admin@example.test",
            setupBefore = TestExecutionEvent.TEST_EXECUTION)
    public void allowsAdminToUpdateAnotherUser() throws Exception {
        UpdateUserProfileRequest profileRequest = new UpdateUserProfileRequest("AdminUpdated", "UpdatedByAdmin");
        mockMvc.perform(put("/api/users/{id}", firstId)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(profileRequest)))
                .andExpect(status().isOk());
        UserSummaryDTO user = jdbcClient.sql("SELECT username, display_name FROM users WHERE id = :id")
                .param("id", firstId)
                .query(UserSummaryDTO.class)
                .single();

        assertThat(user.getUsername()).isEqualTo("AdminUpdated");
        assertThat(user.getDisplayName()).isEqualTo("UpdatedByAdmin");
    }






}
