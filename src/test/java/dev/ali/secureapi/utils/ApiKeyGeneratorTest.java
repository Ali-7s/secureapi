package dev.ali.secureapi.utils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

import static org.assertj.core.api.Assertions.assertThat;

public class ApiKeyGeneratorTest {
    ApiKeyGenerator apiKeyGenerator = new ApiKeyGenerator();




    @Test
    @DisplayName("generated keys always start with the sk_gin_ prefix")
    public void newSecretKeyPrefixCheck() {
        String key = apiKeyGenerator.newSecretKey();
        assertThat(key).startsWith("sk_gin_");
    }

    @Test
    @DisplayName("two calls never produce the same key")
    public void twoCallsDontProduceSameKey() {
        String key = apiKeyGenerator.newSecretKey();
        String key2 = apiKeyGenerator.newSecretKey();
        assertThat(key).isNotEqualTo(key2);
    }

    @Test
    @DisplayName("hash() returns the same value for the same input and a different one for different input")
    public void sameInputProducesSameHash() throws NoSuchAlgorithmException {
        String hashedTest = apiKeyGenerator.hash("test");
        String hashedTest2 = apiKeyGenerator.hash("test");
        String hashedGoodbye = apiKeyGenerator.hash("Goodbye");

        assertThat(hashedTest).isEqualTo(hashedTest2);
        assertThat(hashedGoodbye).isNotEqualTo(hashedTest);
        assertThat(hashedGoodbye).isNotEqualTo(hashedTest2);
    }
}
