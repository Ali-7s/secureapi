package dev.ali.secureapi.enums;

import lombok.Getter;

import java.util.Set;

@Getter
public enum Role {
    USER(Set.of(Permission.POST_READ, Permission.POST_DELETE_OWN)),
    ADMIN(Set.of(
            Permission.POST_READ,
            Permission.POST_DELETE_OWN,
            Permission.POST_DELETE_ANY,
            Permission.SECURITY_EVENTS_READ
    ));

    private final Set<Permission> permissions;

    Role(Set<Permission> permissions) {
        this.permissions = permissions;
    }

}