package dev.ali.secureapi.repository;


import dev.ali.secureapi.dto.RegisterRequest;
import dev.ali.secureapi.dto.UpdateUserProfileRequest;
import dev.ali.secureapi.dto.UserSummaryDTO;
import dev.ali.secureapi.model.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Repository
@Slf4j
public class UserRepository  {

    private final JdbcClient jdbc;

    public UserRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }


    public List<User> findAll() {
        return jdbc.sql("SELECT * FROM users")
                .query(User.class)
                .list();
    }

    public Optional<User> findById(Long id) {
        return jdbc.sql("SELECT * FROM users WHERE id = :id")
                .param("id", id)
                .query(User.class)
                .optional();
    }

    public Optional<User> findByEmail(String email) {
        return jdbc.sql("SELECT * FROM users WHERE email = :email").param("email", email).query(User.class).optional();
    }

    public UserSummaryDTO createUser(RegisterRequest registerRequest) {
        String sql = "INSERT INTO users (username, display_name, password, email) VALUES (:username, :display_name, :password, :email) RETURNING id, username AS username, display_name AS displayName";
        log.info("Creating user {}", registerRequest.username());
        return jdbc.sql(sql).params(Map.of("username", registerRequest.username(), "display_name", registerRequest.displayName(), "password", registerRequest.password(), "email", registerRequest.email())).query(UserSummaryDTO.class).single();
    }


    public UserSummaryDTO updateUser(UpdateUserProfileRequest updateUserProfileRequest, Long userId) {
        String sql = "UPDATE users SET username = COALESCE(:username, username), display_name = COALESCE(:display_name, display_name) WHERE id = :userId RETURNING id, username, display_name";
        HashMap<String, Object> hashMap = new HashMap<>();
        hashMap.put("username", updateUserProfileRequest.username());
        hashMap.put("display_name", updateUserProfileRequest.displayName());
        hashMap.put("userId", userId);

        return jdbc.sql(sql).params(hashMap).query(UserSummaryDTO.class).single();
    }
}
