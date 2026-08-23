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
    private final LockoutService lockoutService;


    public AuthService(CustomAuthenticationProvider authenticationProvider, JWTService jwtService, UserService userService, UserRepository userRepository, CookieService cookieService, PasswordEncoder passwordEncoder, RefreshTokenRepository refreshTokenRepository, ApplicationEventPublisher publisher, LockoutService lockoutService) {
        this.authenticationProvider = authenticationProvider;
        this.jwtService = jwtService;
        this.userService = userService;
        this.cookieService = cookieService;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokenRepository = refreshTokenRepository;
        this.publisher = publisher;
        this.lockoutService = lockoutService;
    }

    public UserSummaryDTO registerUser(String username, String displayName, String email, String password, HttpServletResponse response) {
        RegisterRequest user = new RegisterRequest(email, username, displayName, passwordEncoder.encode(password));
        return userService.createUser(user);
    }

    public UserSummaryDTO loginUser(String email, String password, HttpServletResponse response) throws JsonProcessingException {
        if(lockoutService.isLocked(email)) {
            publisher.publishEvent(new SecurityContextEvent(this, SecurityEventType.AUTH_FAILURE, email, Map.of()));
            throw new ApiException(401, "Incorrect email or password. Please try again.", null);
        }

        try {

            Authentication auth = authenticationProvider.authenticate(
                    new UsernamePasswordAuthenticationToken(email, password)
            );


            log.info("Authentication successful for: {}", email);

            User user = userService.findByEmail(auth.getName())
                    .orElseThrow(() -> new ApiException(404, "User not found after authentication", null));

            refreshTokenRepository.revoke(user.getId());
            UserSummaryDTO userSummaryDTO = new UserSummaryDTO();
            userSummaryDTO.setId(user.getId());
            userSummaryDTO.setUsername(user.getUsername());
            userSummaryDTO.setDisplayName(user.getDisplayName());

            publisher.publishEvent(new SecurityContextEvent(this, SecurityEventType.AUTH_SUCCESS, email, Map.of("status", "success")));

            String accessToken = jwtService.generateAccessToken(userSummaryDTO.getId());
            String refreshToken = jwtService.generateRefreshToken(userSummaryDTO.getId());

            cookieService.addCookie(response, accessToken, "access_token", 3600);
            cookieService.addCookie(response, refreshToken, "refresh_token", 86400);

            return userSummaryDTO;

        } catch (AuthenticationException e) {
            log.warn("Authentication failed for user: {} - Reason: {}", email, e.getMessage());
            publisher.publishEvent(new SecurityContextEvent(this, SecurityEventType.AUTH_FAILURE, email, Map.of("failure", e.getMessage())));
            lockoutService.recordFailure(email);
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

        Long userId = Long.valueOf(jwtService.getSubjectFromRefreshToken(refreshToken));
        String jti = jwtService.getRefreshTokenJTI(refreshToken);

        User user = userService.findById(userId);
        RefreshToken dbToken = refreshTokenRepository.findByJti(jti);

        if (dbToken.revokedAt() != null) {
            log.warn("SECURITY ALERT: Refresh token replay detected for user ID: {}. JTI: {}", userId, jti);
            log.info(dbToken.toString());
            publisher.publishEvent(new SecurityContextEvent(this, SecurityEventType.AUTH_REPLAY, user.getEmail(), Map.of("victim userId", userId.toString(), "victim JTI", jti)));
            refreshTokenRepository.revoke(dbToken.userId());
            throw new ApiException(403, "Security violation: Token already used", null);
        }

        if (!jwtService.validateRefreshToken(user, refreshToken)) {
            throw new ApiException(401, "Invalid refresh token", null);
        }

        String newRefreshToken = jwtService.generateRefreshToken(userId);
        String newAccessToken = jwtService.generateAccessToken(userId);
        String newJti = jwtService.getRefreshTokenJTI(newRefreshToken);

        refreshTokenRepository.revoke(jti, newJti);

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
