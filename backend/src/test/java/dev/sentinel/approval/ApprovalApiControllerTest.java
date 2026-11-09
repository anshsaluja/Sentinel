package dev.sentinel.approval;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ResponseStatusException;

class ApprovalApiControllerTest {
    private final ApprovalPersistenceService service = mock(ApprovalPersistenceService.class);
    private final ApprovalApiController controller = new ApprovalApiController(service);

    private static Jwt token(String tenant) {
        return new Jwt("test-token", Instant.parse("2026-01-01T00:00:00Z"),
                Instant.parse("2027-01-01T00:00:00Z"),
                Map.of("alg", "none"), Map.of("sub", "reviewer", "tenant_id", tenant));
    }

    @Test
    void pendingUsesVerifiedTokenTenantNotClientInput() {
        when(service.pending("team-a")).thenReturn(List.of());
        assertEquals(List.of(), controller.pending(token("team-a")));
        verify(service).pending("team-a");
        verifyNoMoreInteractions(service);
    }

    @Test
    void missingTenantCannotReadApprovals() {
        Jwt missing = new Jwt("test-token", Instant.parse("2026-01-01T00:00:00Z"),
                Instant.parse("2027-01-01T00:00:00Z"),
                Map.of("alg", "none"), Map.of("sub", "reviewer"));
        ResponseStatusException error = assertThrows(ResponseStatusException.class,
                () -> controller.pending(missing));
        assertEquals(HttpStatus.FORBIDDEN, error.getStatusCode());
        verifyNoInteractions(service);
    }

    @Test
    void detailLookupIsTenantScopedAndNotFoundIsSanitized() {
        when(service.find("team-a", "req-1")).thenThrow(new IllegalArgumentException("internal"));
        ResponseStatusException error = assertThrows(ResponseStatusException.class,
                () -> controller.find(token("team-a"), "req-1"));
        assertEquals(HttpStatus.NOT_FOUND, error.getStatusCode());
        assertEquals("Approval not found", error.getReason());
        verify(service).find("team-a", "req-1");
    }

    @Test
    void invalidIdentifierIsRejectedBeforeDatabaseAccess() {
        ResponseStatusException error = assertThrows(ResponseStatusException.class,
                () -> controller.find(token("team-a"), "../other"));
        assertEquals(HttpStatus.BAD_REQUEST, error.getStatusCode());
        verifyNoInteractions(service);
    }
}
