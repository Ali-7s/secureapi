package dev.ali.secureapi.controller;

import dev.ali.secureapi.dto.CreatePostRequest;
import dev.ali.secureapi.model.ApiResponse;
import dev.ali.secureapi.model.Post;
import dev.ali.secureapi.service.PostService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/posts")
public class PostController {

    private final PostService postService;

    public PostController(PostService postService) {
        this.postService = postService;
    }

//    @PostMapping
//    public ResponseEntity<ApiResponse<Post>> createPost(@RequestBody @Valid CreatePostRequest request, Authentication auth) {
//        // SECURITY: The Service layer handles XSS sanitization
//        Post post = postService.createPost(request.content(), auth.getName());
//        return ResponseEntity.ok(ApiResponse.success("Post created", post));
//    }

    @GetMapping
    public ResponseEntity<ApiResponse<List<Post>>> getAllPosts(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        return ResponseEntity.ok(ApiResponse.success("Posts retrieved", postService.findAll(page, size)));
    }

//    @GetMapping("/search")
//    public ResponseEntity<ApiResponse<List<Post>>> searchPosts(
//            @RequestParam String query,
//            @RequestParam(defaultValue = "0") int page,
//            @RequestParam(defaultValue = "10") int size) {
//        // SECURITY: Service uses parameterized SQL to prevent Injection
//        return ResponseEntity.ok(ApiResponse.success("Search results", postService.searchPosts(query, page, size)));
//    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> deletePost(@PathVariable Long id, Authentication auth) {
        log.info("Delete post with id {} with auth {}", id,  auth.getName());
        // TODO:  SECURITY: Service checks if auth.getName() == post.owner
        postService.deletePost(id, auth.getName());
        return ResponseEntity.ok(ApiResponse.success("Post deleted", null));
    }
}