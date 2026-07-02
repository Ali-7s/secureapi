package dev.ali.secureapi.controller;

import dev.ali.secureapi.dto.UserSummaryDTO;
import dev.ali.secureapi.model.ApiResponse;
import dev.ali.secureapi.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<UserSummaryDTO>> getUserProfile(@PathVariable Long id) {
        UserSummaryDTO userSummaryDTO = new UserSummaryDTO(userService.findById(id));
        return ResponseEntity.ok(ApiResponse.success("User profile", userSummaryDTO));
    }

//    @PutMapping("/{id}")
//    public ResponseEntity<ApiResponse<UserSummaryDTO>> updateUser(
//            @PathVariable Long id,
//            @RequestBody @Valid UpdateUserProfileRequest request,
//            Authentication auth) {
//
//        // SECURITY: The Service must throw 403 Forbidden if auth.getName()
//        // does not belong to the user with ID {id}.
//        UserSummaryDTO updatedUser = userService.updateUser(id, request, auth.getName());
//        return ResponseEntity.ok(ApiResponse.success("Profile updated", updatedUser));
//    }
}