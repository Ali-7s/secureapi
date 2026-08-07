package dev.ali.secureapi.service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Service;

@Service
public class CookieService {

    public void addCookie(HttpServletResponse response, String token, String tokenName, int expiresIn) {
        var cookie = new Cookie(tokenName, token);
        cookie.setHttpOnly(true);
        // Must be true in production to prevent tokens from being sent over unencrypted HTTP
        cookie.setSecure(true);
        cookie.setMaxAge(expiresIn);

        // Ensure paths are consistent across the application
        String path = tokenName.equals("access_token") ? "/api" : "/api/auth/refresh";
        cookie.setPath(path);

        // Strict is generally preferred for sensitive auth tokens in an API context
        cookie.setAttribute("SameSite", "Strict");
        response.addCookie(cookie);
    }

    public void removeCookie(HttpServletResponse response, String tokenName) {
        // Deletion cookies must mirror the metadata of the creation cookies exactly
        Cookie cookie = new Cookie(tokenName, "");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setMaxAge(0); // Immediately expires the cookie

        // Path must match the creation path exactly for the browser to clear it
        String path = tokenName.equals("access_token") ? "/api" : "/api/auth/refresh";
        cookie.setPath(path);

        // SameSite should match original to ensure consistent browser behavior
        cookie.setAttribute("SameSite", "Strict");
        response.addCookie(cookie);
    }
}
