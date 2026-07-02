package dev.ali.secureapi.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import dev.ali.secureapi.config.CustomAuthenticationProvider;
import dev.ali.secureapi.dto.RegisterRequest;
import dev.ali.secureapi.dto.UserSummaryDTO;
import dev.ali.secureapi.enums.SecurityEventType;
import dev.ali.secureapi.exception.ApiException;
import dev.ali.secureapi.exception.ResourceNotFoundException;
import dev.ali.secureapi.model.RefreshToken;
import dev.ali.secureapi.model.SecurityContextEvent;
import dev.ali.secureapi.model.User;
import dev.ali.secureapi.repository.RefreshTokenRepository;
import dev.ali.secureapi.repository.UserRepository;
import dev.ali.secureapi.utils.SecurityUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


import java.util.Map;

@Service
@Slf4j
public class AuthService {
    private final CustomAuthenticationProvider authenticationProvider;
    private final JWTService jwtService;
    private final UserService userService;
    private final CookieService cookieService;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenRepository refreshTokenRepository;
    private final ApplicationEventPublisher publisher;


    public AuthService(CustomAuthenticationProvider authenticationProvider, JWTService jwtService, UserService userService, UserRepository userRepository, CookieService cookieService, PasswordEncoder passwordEncoder, RefreshTokenRepository refreshTokenRepository, ApplicationEventPublisher publisher) {
        this.authenticationProvider = authenticationProvider;
        this.jwtService = jwtService;
        this.userService = userService;
        this.cookieService = cookieService;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokenRepository = refreshTokenRepository;
        this.publisher = publisher;
    }

    public UserSummaryDTO registerUser(String username, String displayName, String email, String password, HttpServletResponse response) {
        RegisterRequest user = new RegisterRequest(email, username, displayName, passwordEncoder.encode(password));
        return userService.createUser(user);
    }

// TODO: Add Bucket4J Rate Limiter?
public UserSummaryDTO loginUser(String email, String password, HttpServletResponse response) throws JsonProcessingException {
    log.info("Attempting login for user: {}", email);

    try {
        // 1. The Critical Junction: This is where Spring Security does the heavy lifting.
        // If credentials are wrong, this throws an AuthenticationException immediately.
        Authentication auth = authenticationProvider.authenticate(
                new UsernamePasswordAuthenticationToken(email, password)
        );

        // 2. Success Path
        log.info("Authentication successful for: {}", email);

        User user = userService.findByEmail(auth.getName())
                .orElseThrow(() -> new ApiException(404, "User not found after authentication", null));

        UserSummaryDTO userSummaryDTO = new UserSummaryDTO();
        userSummaryDTO.setId(user.getId());
        userSummaryDTO.setUsername(user.getUsername());
        userSummaryDTO.setDisplayName(user.getDisplayName());

        // Publish SUCCESS event (for your audit trail/baseline)
        publisher.publishEvent(new SecurityContextEvent(this,SecurityEventType.AUTH_SUCCESS, email,Map.of("status", "success")));

        // Token generation
        String accessToken = jwtService.generateAccessToken(userSummaryDTO.getId());
        String refreshToken = jwtService.generateRefreshToken(userSummaryDTO.getId());

        cookieService.addCookie(response, accessToken, "access_token", 3600);
        cookieService.addCookie(response, refreshToken, "refresh_token", 86400);

        return userSummaryDTO;

    } catch (AuthenticationException e) {
        // 3. Failure Path: Caught before the GlobalExceptionHandler sees it.
        log.warn("Authentication failed for user: {} - Reason: {}", email, e.getMessage());

        // Publish FAILURE event (This is what your Detection Engine scans!)
        publisher.publishEvent(new SecurityContextEvent(this, SecurityEventType.AUTH_FAILURE, email, Map.of("failure", e.getMessage())));
        // Re-throw so the GlobalExceptionHandler can send the 401/403 response
        throw e;
    }
}
    @Transactional
    public void refreshAccessToken(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = jwtService.getTokenFromCookies(request, "refresh_token");
        log.info("Refresh access token: {}", refreshToken);
        if (refreshToken == null) {
            throw new ApiException(401, "Refresh token is missing", null);
        }

        // Verify JWT signature and expiration before checking DB
        Long userId = Long.valueOf(jwtService.getSubjectFromRefreshToken(refreshToken));
        String jti = jwtService.getRefreshTokenJTI(refreshToken);

        User user = userService.findById(userId);
        RefreshToken dbToken = refreshTokenRepository.findByJti(jti);

        // Replay Detection: If token is already revoked, it's a security event
        if (dbToken.revokedAt() != null) {
            log.warn("SECURITY ALERT: Refresh token replay detected for user ID: {}. JTI: {}", userId, jti);
            log.info(dbToken.toString());
            refreshTokenRepository.revoke(dbToken.userId());
            throw new ApiException(403, "Security violation: Token already used", null);
        }

        // Validate the token matches the user
        if (!jwtService.validateRefreshToken(user, refreshToken)) {
            throw new ApiException(401, "Invalid refresh token", null);
        }

        // Rotation: Issue new pair and revoke old one
        String newRefreshToken = jwtService.generateRefreshToken(userId);
        String newAccessToken = jwtService.generateAccessToken(userId);
        String newJti = jwtService.getRefreshTokenJTI(newRefreshToken);

        // Revoke old token with guard: revoked_at IS NULL
        refreshTokenRepository.revoke(jti, newJti);

        // Add cookies to response
        cookieService.addCookie(response, newAccessToken, "access_token", 3600);
        cookieService.addCookie(response, newRefreshToken, "refresh_token", 86400);
    }


    @Transactional
    public void logout(Authentication auth, HttpServletResponse response) {
        String email = auth.getName();
        User user = userService.findByEmail(email).orElseThrow();
        cookieService.removeCookie(response, "access_token");
        cookieService.removeCookie(response, "refresh_token");
        refreshTokenRepository.revoke(user.getId());
        SecurityContextHolder.clearContext();
    }


    public UserSummaryDTO getAuthedUser(Authentication authentication) {
        User auth = SecurityUtils.getCurrentUser(authentication);
        User user = userService.findByEmail(auth.getEmail())
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + auth.getEmail()));
        return new UserSummaryDTO(user);
    }
}
