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
    private final TransactionalApprovalService transitions = mock(TransactionalApprovalService.class);
    private final ApprovalApiController controller = new ApprovalApiController(service, transitions);

    private static Jwt token(String tenant) {
        return new Jwt("test-token", Instant.parse("2026-01-01T00:00:00Z"),
                Instant.parse("2027-01-01T00:00:00Z"),
                Map.of("alg", "none"), Map.of("sub", "reviewer", "tenant_id", tenant,
                        "realm_access", Map.of("roles", List.of("sentinel-reviewer"))));
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
    void ordinaryAuthenticatedUserCannotReadQueue() {
        Jwt ordinary = new Jwt("test-token", Instant.parse("2026-01-01T00:00:00Z"),
                Instant.parse("2027-01-01T00:00:00Z"), Map.of("alg", "none"),
                Map.of("sub", "ordinary", "tenant_id", "team-a"));
        ResponseStatusException error = assertThrows(ResponseStatusException.class,
                () -> controller.pending(ordinary));
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
    @Test
    void reviewerDecisionUsesTokenIdentityAndExpectedVersion() {
        ApprovalApiController.Decision decision = new ApprovalApiController.Decision(
                ApprovalWorkflow.Action.APPROVE, 3L);
        controller.decide(token("team-a"), "req-1", decision);
        verify(transitions).transition(eq("req-1"),
                eq(new ApprovalWorkflow.Actor("team-a", "reviewer", true)),
                eq(ApprovalWorkflow.Action.APPROVE), eq(3L));
    }

    @Test
    void cancellationCannotBeSubmittedThroughReviewerDecisionEndpoint() {
        ResponseStatusException error = assertThrows(ResponseStatusException.class,
                () -> controller.decide(token("team-a"), "req-1",
                        new ApprovalApiController.Decision(ApprovalWorkflow.Action.CANCEL, 0L)));
        assertEquals(HttpStatus.BAD_REQUEST, error.getStatusCode());
        verifyNoInteractions(transitions);
    }

    @Test
    void ordinaryUserCannotSubmitApprovalDecision() {
        Jwt ordinary = new Jwt("test-token", Instant.parse("2026-01-01T00:00:00Z"),
                Instant.parse("2027-01-01T00:00:00Z"), Map.of("alg", "none"),
                Map.of("sub", "ordinary", "tenant_id", "team-a"));
        ResponseStatusException error = assertThrows(ResponseStatusException.class,
                () -> controller.decide(ordinary, "req-1",
                        new ApprovalApiController.Decision(ApprovalWorkflow.Action.APPROVE, 0L)));
        assertEquals(HttpStatus.FORBIDDEN, error.getStatusCode());
        verifyNoInteractions(transitions);
    }

    @Test
    void staleVersionProducesSanitizedConflict() {
        when(transitions.transition(anyString(), any(), any(), anyLong()))
                .thenThrow(new IllegalStateException("internal details"));
        ResponseStatusException error = assertThrows(ResponseStatusException.class,
                () -> controller.decide(token("team-a"), "req-1",
                        new ApprovalApiController.Decision(ApprovalWorkflow.Action.REJECT, 2L)));
        assertEquals(HttpStatus.CONFLICT, error.getStatusCode());
        assertEquals("Approval cannot be updated", error.getReason());
    }


    @Test
    void adminCanReviewUsingTheirOwnIdentity() {
        Jwt admin = new Jwt("test-token", Instant.parse("2026-01-01T00:00:00Z"),
                Instant.parse("2027-01-01T00:00:00Z"), Map.of("alg", "none"),
                Map.of("sub", "admin-42", "tenant_id", "team-a",
                        "realm_access", Map.of("roles", List.of("sentinel-admin"))));
        controller.decide(admin, "req-1",
                new ApprovalApiController.Decision(ApprovalWorkflow.Action.REJECT, 1L));
        verify(transitions).transition("req-1",
                new ApprovalWorkflow.Actor("team-a", "admin-42", true),
                ApprovalWorkflow.Action.REJECT, 1L);
    }

    @Test
    void missingReviewerSubjectIsRejectedBeforeTransition() {
        Jwt noSubject = new Jwt("test-token", Instant.parse("2026-01-01T00:00:00Z"),
                Instant.parse("2027-01-01T00:00:00Z"), Map.of("alg", "none"),
                Map.of("tenant_id", "team-a",
                        "realm_access", Map.of("roles", List.of("sentinel-reviewer"))));
        ResponseStatusException error = assertThrows(ResponseStatusException.class,
                () -> controller.decide(noSubject, "req-1",
                        new ApprovalApiController.Decision(ApprovalWorkflow.Action.APPROVE, 0L)));
        assertEquals(HttpStatus.FORBIDDEN, error.getStatusCode());
        verifyNoInteractions(transitions);
    }

    @Test
    void negativeVersionIsRejectedBeforeTransition() {
        ResponseStatusException error = assertThrows(ResponseStatusException.class,
                () -> controller.decide(token("team-a"), "req-1",
                        new ApprovalApiController.Decision(ApprovalWorkflow.Action.APPROVE, -1L)));
        assertEquals(HttpStatus.BAD_REQUEST, error.getStatusCode());
        verifyNoInteractions(transitions);
    }

    @Test
    void missingDecisionIsRejectedBeforeTransition() {
        ResponseStatusException error = assertThrows(ResponseStatusException.class,
                () -> controller.decide(token("team-a"), "req-1", null));
        assertEquals(HttpStatus.BAD_REQUEST, error.getStatusCode());
        verifyNoInteractions(transitions);
    }

    @Test
    void decisionIdentifierIsValidatedBeforeTransition() {
        ResponseStatusException error = assertThrows(ResponseStatusException.class,
                () -> controller.decide(token("team-a"), "../other",
                        new ApprovalApiController.Decision(ApprovalWorkflow.Action.APPROVE, 0L)));
        assertEquals(HttpStatus.BAD_REQUEST, error.getStatusCode());
        verifyNoInteractions(transitions);
    }

}
