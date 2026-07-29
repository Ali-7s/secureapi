package dev.ali.secureapi.service;

import dev.ali.secureapi.dto.RegisterRequest;
import dev.ali.secureapi.dto.UpdateUserProfileRequest;
import dev.ali.secureapi.dto.UserSummaryDTO;
import dev.ali.secureapi.exception.ApiException;
import dev.ali.secureapi.exception.ResourceNotFoundException;
import dev.ali.secureapi.model.User;
import dev.ali.secureapi.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final AuthzService authzService;

    public User findById(Long id){
        Optional<User> user = userRepository.findById(id);
        if(user.isPresent()){
            return user.get();
        } else
            throw new ResourceNotFoundException("User not found");
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public UserSummaryDTO createUser(RegisterRequest registerRequest) {

        try {
            return userRepository.createUser(registerRequest);
        } catch (DuplicateKeyException ex) {
            throw new ApiException(409, "An account with this email or username already exists.", null);
        }
    }

    public UserSummaryDTO updateUser(Long userId, Long requesterId, boolean isAdmin, UpdateUserProfileRequest updateUserProfileRequest) {
        authzService.requireOwnerOrAdmin(userId, requesterId, isAdmin);
        return userRepository.updateUser(updateUserProfileRequest, userId);
    }


}

