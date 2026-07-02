package dev.ali.secureapi.model;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.LocalDateTime;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiResponse<T>(
        LocalDateTime timestamp,
        String message,
        T data,
        Object errors
) {
    public static <T> ApiResponse<T> success(String message, T data) {
        return new ApiResponse<>(LocalDateTime.now(),  message, data, null);
    }

    public static ApiResponse<Void> error( String message, Object errors) {
        return new ApiResponse<>(LocalDateTime.now(),  message, null, errors);
    }
}


