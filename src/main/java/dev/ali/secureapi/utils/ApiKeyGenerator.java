package dev.ali.secureapi.utils;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class ApiKeyGenerator {


    public String newSecretKey() {
        byte[] secretKey = new byte[32];
        new SecureRandom().nextBytes(secretKey);
        String rand = Base64.getUrlEncoder().withoutPadding().encodeToString(secretKey);
        return "sk_gin_" + rand;
    }

    public String hash(String plaintextKey) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(plaintextKey.getBytes(StandardCharsets.UTF_8));
        String stored = Base64.getEncoder().encodeToString(digest);
        return stored;
    }

    public boolean matches(String plaintext, String storedHash) throws NoSuchAlgorithmException {
        return MessageDigest.isEqual(hash(plaintext).getBytes(), storedHash.getBytes());
    }
}
