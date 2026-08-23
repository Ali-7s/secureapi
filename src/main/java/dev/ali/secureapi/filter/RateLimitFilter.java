package dev.ali.secureapi.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.ali.secureapi.enums.SecurityEventType;
import dev.ali.secureapi.exception.ApiException;
import dev.ali.secureapi.model.ApiResponse;
import dev.ali.secureapi.model.SecurityContextEvent;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;


@Component
public class RateLimitFilter extends OncePerRequestFilter {
    private final ApplicationEventPublisher publisher;
    private final Duration refillPeriod;
    private final long capacity;
    private final ConcurrentHashMap<String, Bucket> bucketMap = new ConcurrentHashMap<>();
    private final ObjectMapper objectMapper;


    public RateLimitFilter(ApplicationEventPublisher publisher, @Value("${rate-limit.refill-period:PT1M}") Duration refillPeriod, @Value("${rate-limit.capacity:20}") long capacity, ObjectMapper objectMapper) {
        this.publisher = publisher;
        this.refillPeriod = refillPeriod;
        this.capacity = capacity;
        this.objectMapper = objectMapper;
    }

    private Bucket createNewBucket() {
        return Bucket.builder().addLimit(limit -> limit.capacity(capacity).refillGreedy(capacity, refillPeriod)).build();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String ip = request.getRemoteAddr();
        Bucket bucket = bucketMap.computeIfAbsent(ip, key -> createNewBucket());
        ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);

        if(probe.isConsumed()) {
            filterChain.doFilter(request, response);
        } else {
            publisher.publishEvent(new SecurityContextEvent(this, SecurityEventType.RATE_LIMIT_HIT, null, Map.of()));
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setHeader("X-Rate-Limit-Retry-After-Seconds", "" + TimeUnit.NANOSECONDS.toSeconds(probe.getNanosToWaitForRefill()));
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding("UTF-8");
            response.getWriter().print(objectMapper.writeValueAsString(ApiResponse.error("Too many requests", null)));
        }

    }


    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return !(path.equals("/api/auth/login") || path.equals("/api/auth/register"));
    }
}
