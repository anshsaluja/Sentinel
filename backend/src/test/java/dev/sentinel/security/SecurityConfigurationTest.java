package dev.sentinel.security;

import static org.junit.jupiter.api.Assertions.*;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.web.cors.CorsConfiguration;

/** CORS is restricted to the local Angular demo, never arbitrary origins. */
class SecurityConfigurationTest {
    private final SecurityConfiguration security = new SecurityConfiguration();

    @Test
    void allowsOnlyLocalAngularOriginsForApiPreflight() {
        var source = security.corsConfigurationSource();
        var request = new org.springframework.mock.web.MockHttpServletRequest("OPTIONS", "/api/v1/policies/evaluate");
        CorsConfiguration config = source.getCorsConfiguration(request);
        assertNotNull(config);
        assertEquals(List.of("http://localhost:4200", "http://127.0.0.1:4200"), config.getAllowedOrigins());
        assertEquals("http://localhost:4200", config.checkOrigin("http://localhost:4200"));
        assertEquals("http://127.0.0.1:4200", config.checkOrigin("http://127.0.0.1:4200"));
        assertNull(config.checkOrigin("https://attacker.example"));
        assertNull(config.checkOrigin("http://localhost:4300"));
        assertEquals(List.of("POST", "OPTIONS"), config.getAllowedMethods());
        assertEquals(Boolean.FALSE, config.getAllowCredentials());
    }

    @Test
    void doesNotExposeCorsPolicyOutsideApi() {
        var request = new org.springframework.mock.web.MockHttpServletRequest("OPTIONS", "/admin");
        assertNull(security.corsConfigurationSource().getCorsConfiguration(request));
    }
}
