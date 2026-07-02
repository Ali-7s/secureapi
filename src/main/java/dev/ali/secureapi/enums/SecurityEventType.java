package dev.ali.secureapi.enums;

public enum SecurityEventType {
    // authentication
    AUTH_SUCCESS,
    AUTH_FAILURE,
    AUTH_REPLAY,
    AUTH_LOGOUT,
    // authorization
    AUTHZ_DENIED,
    AUTHZ_IDOR,

    // jwt
    JWT_EXPIRED,
    JWT_TAMPERED,
    JWT_MALFORMED,

    // sys
    RATE_LIMIT_HIT,
    GEO_MISMATCH,
    ACCOUNT_LOCKED
}
