package dev.ali.secureapi.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import dev.ali.secureapi.dto.LoginRequest;
import dev.ali.secureapi.dto.RegisterRequest;
import dev.ali.secureapi.dto.UserSummaryDTO;
import dev.ali.secureapi.model.ApiResponse;
import dev.ali.secureapi.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import static dev.ali.secureapi.model.ApiResponse.success;

@RestController
@RequestMapping("/api/auth")
@Slf4j
public class AuthController {
    private final AuthService authService;


    public AuthController(AuthService authService) {
        this.authService = authService;

    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<UserSummaryDTO>> registerUser(@Valid @RequestBody RegisterRequest registerRequest, HttpServletResponse response) {
        UserSummaryDTO user = authService.registerUser(
                registerRequest.username(),
                registerRequest.displayName(),
                registerRequest.email(),
                registerRequest.password(),
                response
        );
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(success("Account created", user));
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<UserSummaryDTO>> loginUser(
            @RequestBody @Valid LoginRequest loginRequest,
            HttpServletResponse response
    ) throws JsonProcessingException {

        // TODO: ON ANOTHER LOGIN REVOKE ANY EXISTING TOKENS? OTHERWISE CAN SPAM LOGIN WITH A LOT OF ACTIVE REFRESH TOKENS
        UserSummaryDTO user = authService.loginUser(loginRequest.email(), loginRequest.password(), response);

        return ResponseEntity.ok(success("Successfully logged in", user));
    }


    @GetMapping("/refresh")
    public ResponseEntity<ApiResponse<Void>> refreshAccessToken(HttpServletResponse response, HttpServletRequest request) {
        authService.refreshAccessToken(request, response);
        return ResponseEntity.ok(success("Access token refreshed", null));

    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(Authentication authentication, HttpServletResponse response) {

        authService.logout(authentication, response);
        return ResponseEntity.ok(success("Logout success", null));

    }

    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserSummaryDTO>> getCurrentUser(Authentication authentication) {
        UserSummaryDTO user = authService.getAuthedUser(authentication);
        log.info("Current user: {}", user);
        return ResponseEntity.ok(success("Authenticated user retrieved", user));
    }

}
