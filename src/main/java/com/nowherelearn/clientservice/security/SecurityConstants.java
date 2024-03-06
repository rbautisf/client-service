package com.nowherelearn.clientservice.security;

public final class SecurityConstants {
    public static String[] AUTH_WHITELIST = {
            "/actuator",
            "/swagger-ui/**",
            "/api-docs/**",
            "/assets/**",
            "/webjars/**",
            "/logged-out"
    };
    public static final String ROLES_CLAIM = "roles";

    public static final String DEFAULT_AUTHORITY_PREFIX = "ROLE_";

    private SecurityConstants() {
    }
}
