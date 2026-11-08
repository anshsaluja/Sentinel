package dev.sentinel.approval;

import dev.sentinel.audit.AuditDocument;
import dev.sentinel.audit.AuditHistoryService;
import dev.sentinel.audit.AuditRepository;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DuplicateKeyException;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class TransactionalApprovalServiceTest {
    private final ApprovalRepository approvals = mock(ApprovalRepository.class);
    private final AuditRepository audits = mock(AuditRepository.class);
    private final AuditHistoryService history = mock(AuditHistoryService.class);
    private final Instant now = Instant.parse("2026-11-08T10:00:00Z");
    private final TransactionalApprovalService service = new TransactionalApprovalService(
            approvals, audits, history, Clock.fixed(now, ZoneOffset.UTC));

    private ApprovalDocument pending() {
        return new ApprovalDocument(new ApprovalWorkflow.Request("req-1", "tenant-a",
                "alice", null, "ledger", "Quarterly review",
                ApprovalWorkflow.Status.PENDING, 0, now.minusSeconds(60)));
    }

    @Test void savesApprovalAndChainedAuditEvent() {
        when(approvals.findByIdAndTenantId("req-1", "tenant-a"))
                .thenReturn(Optional.of(pending()));
        when(history.verifiedHistory("tenant-a")).thenReturn(List.of());
        when(approvals.save(any())).thenAnswer(inv -> {
            ApprovalDocument saved = inv.getArgument(0);
            assertEquals(0L, saved.version);
            saved.version = 1L;
            return saved;
        });
        var result = service.transition("req-1",
                new ApprovalWorkflow.Actor("tenant-a", "bob", true),
                ApprovalWorkflow.Action.APPROVE, 0);
        assertEquals(ApprovalWorkflow.Status.APPROVED, result.status());
        verify(audits).save(argThat(doc -> "tenant-a".equals(doc.tenantId)
                && "bob".equals(doc.actorId)
                && "ACCESS_REQUEST_APPROVE".equals(doc.action)
                && doc.sequence == 1));
    }

    @Test void crossTenantRecordCannotBeWritten() {
        when(approvals.findByIdAndTenantId("req-1", "tenant-b"))
                .thenReturn(Optional.of(pending()));
        assertThrows(SecurityException.class, () -> service.transition("req-1",
                new ApprovalWorkflow.Actor("tenant-b", "bob", true),
                ApprovalWorkflow.Action.APPROVE, 0));
        verifyNoInteractions(audits, history);
        verify(approvals, never()).save(any());
    }

    @Test void selfApprovalCannotBeWritten() {
        when(approvals.findByIdAndTenantId("req-1", "tenant-a"))
                .thenReturn(Optional.of(pending()));
        when(history.verifiedHistory("tenant-a")).thenReturn(List.of());
        assertThrows(SecurityException.class, () -> service.transition("req-1",
                new ApprovalWorkflow.Actor("tenant-a", "alice", true),
                ApprovalWorkflow.Action.APPROVE, 0));
        verify(approvals, never()).save(any());
        verifyNoInteractions(audits);
    }

    @Test void auditInsertFailureIsNotSwallowed() {
        when(approvals.findByIdAndTenantId("req-1", "tenant-a"))
                .thenReturn(Optional.of(pending()));
        when(history.verifiedHistory("tenant-a")).thenReturn(List.of());
        when(approvals.save(any())).thenAnswer(inv -> {
            ApprovalDocument saved = inv.getArgument(0);
            saved.version = 1L;
            return saved;
        });
        when(audits.save(any(AuditDocument.class)))
                .thenThrow(new DuplicateKeyException("competing audit writer"));
        assertThrows(DuplicateKeyException.class, () -> service.transition("req-1",
                new ApprovalWorkflow.Actor("tenant-a", "bob", true),
                ApprovalWorkflow.Action.APPROVE, 0));
    }

    @Test void staleVersionCannotBeWritten() {
        when(approvals.findByIdAndTenantId("req-1", "tenant-a"))
                .thenReturn(Optional.of(pending()));
        when(history.verifiedHistory("tenant-a")).thenReturn(List.of());
        assertThrows(IllegalStateException.class, () -> service.transition("req-1",
                new ApprovalWorkflow.Actor("tenant-a", "bob", true),
                ApprovalWorkflow.Action.APPROVE, 7));
        verify(approvals, never()).save(any());
        verifyNoInteractions(audits);
    }
}
