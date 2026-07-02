package dev.ali.secureapi.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import dev.ali.secureapi.config.JwtProperties;
import dev.ali.secureapi.model.User;
import dev.ali.secureapi.repository.RefreshTokenRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Date;
import java.util.Objects;
import java.util.UUID;

@Service
public class JWTService {

    private static final long ACCESS_TOKEN_EXPIRATION_MS = 3_600_000; // 1 hour
    private static final long REFRESH_TOKEN_EXPIRATION_MS = 86_400_000; // 1 day

    private final Algorithm accessTokenAlgorithm;
    private final Algorithm refreshTokenAlgorithm;
    private final JWTVerifier accessTokenVerifier;
    private final JWTVerifier refreshTokenVerifier;
    private final RefreshTokenRepository refreshTokenRepository;


    public JWTService(RefreshTokenRepository refreshTokenRepository, @Valid JwtProperties jwtProperties) {
        this.accessTokenAlgorithm = Algorithm.HMAC256(jwtProperties.access().secret().getBytes());
        this.refreshTokenAlgorithm = Algorithm.HMAC256(jwtProperties.refresh().secret().getBytes());
        this.refreshTokenRepository = refreshTokenRepository;
        this.accessTokenVerifier = buildVerifier(accessTokenAlgorithm);
        this.refreshTokenVerifier = buildVerifier(refreshTokenAlgorithm);
    }

    public String generateAccessToken(Long userId) {
        return JWT.create()
                .withSubject(userId.toString())
                .withExpiresAt(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRATION_MS))
                .withIssuedAt(new Date())
                .sign(accessTokenAlgorithm);
    }

    public String generateRefreshToken(Long userId) {
        UUID uuid = UUID.randomUUID();
        Date issuedAt = new Date();
        Date expiresAt = new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRATION_MS);
        String jwt =  JWT.create()
                .withJWTId(uuid.toString())
                .withSubject(userId.toString())
                .withExpiresAt(expiresAt)
                .withIssuedAt(issuedAt)
                .sign(refreshTokenAlgorithm);
        refreshTokenRepository.insert(userId, uuid.toString(), expiresAt.toInstant(), issuedAt.toInstant());
        return jwt;
    }
    public boolean validateRefreshToken(User user, String token) {
        try {
            DecodedJWT decodedJWT = refreshTokenVerifier.verify(token);
            return Objects.equals(decodedJWT.getSubject(), user.getId().toString());
        } catch (JWTVerificationException e) {
            return false;
        }
    }

    public boolean validateAccessToken(String token) {
        try {
            accessTokenVerifier.verify(token);
            return true;
        } catch (JWTVerificationException e) {
            return false;
        }
    }

    public String getSubjectFromAccessToken(String token) {
        try {
            return accessTokenVerifier.verify(token).getSubject();
        } catch (JWTVerificationException e) {
            throw new JWTVerificationException("Invalid access token", e);
        }
    }

    public String getSubjectFromRefreshToken(String token) {
        try {
            return refreshTokenVerifier.verify(token).getSubject();
        } catch (JWTVerificationException e) {
            throw new JWTVerificationException("Invalid refresh token", e);
        }
    }

    private JWTVerifier buildVerifier(Algorithm algorithm) {
        try {
            return JWT.require(algorithm).build();
        } catch (JWTVerificationException exception) {
            throw new JWTVerificationException("Error building JWT verifier", exception);
        }
    }

    public String getTokenFromCookies(HttpServletRequest request, String cookieName) {
        if (request.getCookies() == null) {
            return null;
        }
        return Arrays.stream(request.getCookies())
                .filter(c -> c.getName().equals(cookieName))
                .findFirst()
                .map(Cookie::getValue)
                .orElse(null);
    }

    public String getRefreshTokenJTI(HttpServletRequest request) {
        DecodedJWT decodedJWT = refreshTokenVerifier.verify(getTokenFromCookies(request, "refresh_token"));
        return decodedJWT.getId();
    }

    public String getRefreshTokenJTI(String token) {
        DecodedJWT decodedJWT = refreshTokenVerifier.verify(token);
        return decodedJWT.getId();
    }

}
