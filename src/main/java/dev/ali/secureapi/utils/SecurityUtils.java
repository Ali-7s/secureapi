package dev.ali.secureapi.utils;

import dev.ali.secureapi.config.CustomUserDetails;
import dev.ali.secureapi.exception.ApiException;
import dev.ali.secureapi.model.User;
import org.springframework.security.core.Authentication;

public class SecurityUtils {

    public static User getCurrentUser(Authentication authentication) {
        if(authentication == null) {
            throw new ApiException(401, "Authentication required. Please log in", null);
        }

        return ((CustomUserDetails) authentication.getPrincipal()).user();
    }

    public static CustomUserDetails getCurrentUserDetails(Authentication authentication) {
        if(authentication == null) {
            throw new ApiException(401, "Authentication required. Please log in", null);
        }

        return ((CustomUserDetails) authentication.getPrincipal());
    }
}
