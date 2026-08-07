package dev.ali.secureapi.enums;

import java.util.HashSet;
import java.util.Set;

public enum ApiKeysScope {
    ALERTS_READ,
    ALERTS_WRITE;


    public static Set<ApiKeysScope> parse(String raw) {
        Set<ApiKeysScope> set = new HashSet<>();
        String[] pieces = raw.split(",");
        for (String piece : pieces) {
            set.add(ApiKeysScope.valueOf(piece.trim()));
        }
        return set;
    }

    ;
}
