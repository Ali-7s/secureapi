package dev.ali.secureapi.filter;

import dev.ali.secureapi.enums.ApiKeysScope;
import dev.ali.secureapi.enums.SecurityEventType;
import dev.ali.secureapi.model.ApiKey;
import dev.ali.secureapi.model.SecurityContextEvent;
import dev.ali.secureapi.repository.ApiKeyRepository;
import dev.ali.secureapi.utils.ApiKeyGenerator;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;

@Component
@RequiredArgsConstructor
public class ApiKeyAuthFilter extends OncePerRequestFilter {
    private final ApiKeyRepository apiKeyRepository;
    private final ApiKeyGenerator apiKeyGenerator;
    private final ApplicationEventPublisher publisher;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if ( auth == null || !auth.isAuthenticated()) {
            String key = request.getHeader("X-API-Key");

            try {
                String hash = apiKeyGenerator.hash(key);
                Optional<ApiKey> repoKey = apiKeyRepository.findActiveByHash(hash);

                if(repoKey.isPresent() && repoKey.get().expiresAt().isAfter(Instant.now()) && repoKey.get().revokedAt() == null) {

                    List<GrantedAuthority> scopes = AuthorityUtils.createAuthorityList(ApiKeysScope.parse(repoKey.get().scopes()).toString());
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(repoKey.get(), null, scopes);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    publisher.publishEvent(new SecurityContextEvent(this, SecurityEventType.API_KEY_USED, repoKey.get().userId().toString(), Map.of("userId", repoKey.get().userId().toString(), "keyPrefix", repoKey.get().keyPrefix(), "scopes", repoKey.get().scopes())));
                    apiKeyRepository.updateLastUsed(repoKey.get().id());
                } else {
                    publisher.publishEvent(new SecurityContextEvent(this, SecurityEventType.API_KEY_REJECTED, null, Map.of("apiKey", hash)));
                }

            } catch (Exception ignored) {

            }
        }


        filterChain.doFilter(request, response);

    }
}
