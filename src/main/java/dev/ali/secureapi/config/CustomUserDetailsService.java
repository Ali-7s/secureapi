package dev.ali.secureapi.config;

import dev.ali.secureapi.model.User;
import dev.ali.secureapi.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Optional<User> user = userRepository.findByEmail(email);

        User actualUser = user.orElseThrow(() -> new UsernameNotFoundException("Bad credentials"));

        return new CustomUserDetails(actualUser);
    }

    public UserDetails loadUserByUserId(Long userId) throws UsernameNotFoundException {
        Optional<User> user = userRepository.findById(userId);
//        This gets converted into a BadCredentials Exception by Spring Boot
        log.info("loadByUserId");
        User actualUser = user.orElseThrow(() -> new UsernameNotFoundException("Bad credentials"));

        return new CustomUserDetails(actualUser);
    }
}
