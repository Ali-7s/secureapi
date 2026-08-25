package dev.ali.secureapi.controller;

import dev.ali.secureapi.dto.UpdateUserProfileRequest;
import dev.ali.secureapi.dto.UserSummaryDTO;
import dev.ali.secureapi.model.ApiResponse;
import dev.ali.secureapi.service.UserService;
import dev.ali.secureapi.utils.SecurityUtils;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<UserSummaryDTO>> getUserProfile(@PathVariable Long id, Authentication auth) {
        Long requesterId = SecurityUtils.getCurrentUser(auth).getId();
        boolean isAdmin = SecurityUtils.isAdmin(auth);

        UserSummaryDTO userSummaryDTO = new UserSummaryDTO(userService.findById(id, requesterId, isAdmin));
        return ResponseEntity.ok(ApiResponse.success("User profile", userSummaryDTO));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ApiResponse<UserSummaryDTO>> updateUser(
            @PathVariable Long id,
            @RequestBody @Valid UpdateUserProfileRequest request,
            Authentication auth) {


        Long requesterId = SecurityUtils.getCurrentUser(auth).getId();
        boolean isAdmin = SecurityUtils.isAdmin(auth);

        UserSummaryDTO updatedUser = userService.updateUser(id, requesterId, isAdmin, request);
        return ResponseEntity.ok(ApiResponse.success("Profile updated", updatedUser));
    }
}