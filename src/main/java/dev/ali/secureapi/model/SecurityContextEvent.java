package dev.ali.secureapi.model;

import dev.ali.secureapi.enums.SecurityEventType;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

import java.util.Map;

@Getter
public class SecurityContextEvent extends ApplicationEvent {
    private final SecurityEventType type;
    private final String principal;
    private final Map<String, String> metadata;

    public SecurityContextEvent(Object source, SecurityEventType type, String principal, Map<String, String> metadata) {
        super(source); // 'source' is usually 'this' (the AuthService)
        this.type = type;
        this.principal = principal;
        this.metadata = metadata;
    }

}