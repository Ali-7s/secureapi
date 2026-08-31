package dev.ali.secureapi.service;
import dev.ali.secureapi.model.User;
import org.junit.jupiter.api.Test;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import dev.ali.secureapi.config.JwtProperties;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

public class JWTServiceTest {
    JwtProperties jwtProperties = new JwtProperties(new JwtProperties.SecretPair("0BXTELB2+ZIkYoxANMelJCEW0yVA3oe6PM2aQ57Jai0="), new JwtProperties.SecretPair("yWSLYhBfPLUeBTgamKwrA+osniC/jtqrmj3Vp/2maSo="));
    JWTService jwtService = new JWTService(null, jwtProperties);
    String falseToken = JWT.create().withSubject("1").sign(Algorithm.HMAC256("w/bONl4PY3WJo2AVXZfWR7dBWxZGv1eskMHuRlxkvhs=".getBytes()));



    @Test
    public void rejectsAccessTokenSignedWithUnknownSecret() {
        assertThat(jwtService.validateAccessToken(falseToken)).isFalse();
    }
    @Test
    public void rejectsRefreshTokenSignedWithUnknownSecret() {
        User user = new User();
        user.setId(1L);
        assertThat(jwtService.validateRefreshToken(user,falseToken)).isFalse();
    }

    @Test
    public void rejectsTokenModifiedAfterSigning() {
      String token =   jwtService.generateAccessToken(1L);
      assertThat(jwtService.validateAccessToken(token + "CHANGED")).isFalse();
    }

    @Test
    public void rejectsAccessTokenUsedAsRefreshToken() {
        User user = new User();
        user.setId(1L);
        assertThat(jwtService.validateRefreshToken(user, jwtService.generateAccessToken(1L))).isFalse();
    }

    @Test
    public void rejectsExpiredToken() {
        String falseToken = JWT.create().withSubject("1").withExpiresAt(new Date(System.currentTimeMillis() - 60_000)).sign(Algorithm.HMAC256(jwtProperties.access().secret()));
        assertThat(jwtService.validateAccessToken(falseToken)).isFalse();
    }



}
