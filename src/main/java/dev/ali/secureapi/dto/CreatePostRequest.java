package dev.ali.secureapi.dto;

import jakarta.validation.constraints.NotEmpty;

public record CreatePostRequest(@NotEmpty(message = "Post content cannot be empty.") String content) {
}
