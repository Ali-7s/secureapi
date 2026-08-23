package dev.ali.secureapi.exception;

import com.auth0.jwt.exceptions.TokenExpiredException;
import dev.ali.secureapi.model.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import jakarta.servlet.http.HttpServletRequest;

import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.HttpStatus.*;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    private final HttpServletRequest servletRequest;

    public GlobalExceptionHandler(HttpServletRequest servletRequest) {
        this.servletRequest = servletRequest;
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Void>> handleValidationException(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(error ->
                errors.put(error.getField(), error.getDefaultMessage())
        );

        String message = "Validation failed: " + errors.values().stream()
                .findFirst()
                .orElse("Invalid input");

        return ResponseEntity.badRequest()
                .body(ApiResponse.error(message, errors));
    }


    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiResponse<Void>> handleResourceNotFound(ResourceNotFoundException ex) {
        return new ResponseEntity<>(ApiResponse.error("The requested resource could not be found.", null), NOT_FOUND);
    }


    @ExceptionHandler(TokenExpiredException.class)
    public ResponseEntity<ApiResponse<Void>> handleTokenExpiredException(TokenExpiredException ex) {
        return new ResponseEntity<>(ApiResponse.error("You are not authorized. Please refresh again.", null), UNAUTHORIZED);

    }

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ApiResponse<Void>> handleApiException(ApiException ex) {
        log.error("API Exception: {}", ex.getMessage());
        HttpStatus status = HttpStatus.valueOf(ex.getStatus());
        return new ResponseEntity<>(ApiResponse.error(ex.getMessage(), ex.getErrors()), status);
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponse<Void>> handleBadCredentials(BadCredentialsException ex) {
        return new ResponseEntity<>(ApiResponse.error("Incorrect email or password. Please try again.", null), UNAUTHORIZED);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleGenericException(Exception ex) {
        log.error("An error occurred at path: {}", servletRequest.getServletPath(), ex);
        return new ResponseEntity<>(ApiResponse.error("An unexpected internal server error occurred.", null), INTERNAL_SERVER_ERROR);
    }


}
