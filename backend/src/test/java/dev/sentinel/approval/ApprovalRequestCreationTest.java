package dev.sentinel.approval;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import dev.sentinel.audit.AuditDocument;
import dev.sentinel.audit.AuditHistoryService;
import dev.sentinel.audit.AuditRepository;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ResponseStatusException;

class ApprovalRequestCreationTest {
    @Test
    void createsPendingRequestAndAuditWithoutCallerControlledTenant() {
        var approvals = mock(ApprovalRepository.class);
        var audits = mock(AuditRepository.class);
        var history = mock(AuditHistoryService.class);
        when(history.verifiedHistory("tenant-a")).thenReturn(List.of());
        when(approvals.save(any(ApprovalDocument.class))).thenAnswer(invocation -> invocation.getArgument(0));
        var clock = Clock.fixed(Instant.parse("2026-11-09T20:00:00Z"), ZoneOffset.UTC);
        var service = new ApprovalRequestService(approvals, audits, history, clock);
        var controller = new ApprovalRequestController(service);
        var jwt = Jwt.withTokenValue("test-only").header("alg", "none")
                .subject("requester-a").claim("tenant_id", "tenant-a").build();

        var created = controller.create(jwt, new ApprovalRequestController.Submission("ledger", "Need read access"));
        assertEquals("tenant-a", created.tenantId());
        assertEquals("requester-a", created.requesterId());
        assertEquals(ApprovalWorkflow.Status.PENDING, created.status());
        assertEquals(0, created.version());
        assertNull(created.approverId());
        verify(audits).save(argThat(event -> event.tenantId.equals("tenant-a")
                && event.actorId.equals("requester-a") && event.action.equals("REQUEST")
                && event.targetId.equals(created.id())));
    }

    @Test
    void rejectsUntrustedIdentityAndInvalidSubmission() {
        var controller = new ApprovalRequestController(mock(ApprovalRequestService.class));
        var missingTenant = Jwt.withTokenValue("test-only").header("alg", "none")
                .subject("alice").build();
        assertThrows(ResponseStatusException.class, () -> controller.create(missingTenant,
                new ApprovalRequestController.Submission("ledger", "needed")));
        assertThrows(ResponseStatusException.class, () -> controller.create(null,
                new ApprovalRequestController.Submission("ledger", "needed")));
        var jwt = Jwt.withTokenValue("test-only").header("alg", "none")
                .subject("alice").claim("tenant_id", "tenant-a").build();
        assertThrows(ResponseStatusException.class, () -> controller.create(jwt, null));
    }

    @Test
    void rejectsBlankJustificationBeforePersistence() {
        var approvals = mock(ApprovalRepository.class);
        var service = new ApprovalRequestService(approvals, mock(AuditRepository.class),
                mock(AuditHistoryService.class));
        assertThrows(IllegalArgumentException.class,
                () -> service.create("tenant-a", "alice", "ledger", "  "));
        verifyNoInteractions(approvals);
    }
}
