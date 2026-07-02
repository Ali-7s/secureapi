package dev.ali.secureapi.exception;

import lombok.Getter;

import java.time.LocalDateTime;
import java.util.Map;

@Getter
public class ApiException extends RuntimeException {
    private final LocalDateTime timestamp;
    private final int status;
    private final Map<String, String> errors;

    public ApiException(int status, String message, Map<String, String> errors) {
        super(message);
        this.timestamp = LocalDateTime.now();
        this.status = status;
        this.errors = errors;
    }

    public ApiException(String message) {
        this(500, message, null);
    }

}
