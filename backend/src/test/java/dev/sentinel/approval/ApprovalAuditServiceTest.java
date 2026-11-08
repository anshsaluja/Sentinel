package dev.sentinel.approval;

import dev.sentinel.audit.AuditChain;
import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class ApprovalAuditServiceTest {
    private static final Instant NOW = Instant.parse("2026-11-08T06:00:00Z");
    private final ApprovalAuditService service = new ApprovalAuditService();
    private final AuditChain chain = new AuditChain();

    private ApprovalWorkflow.Request pending() {
        return new ApprovalWorkflow.Request("req-1", "tenant-a", "alice", null,
                "ledger", "Quarterly review", ApprovalWorkflow.Status.PENDING, 0, NOW);
    }

    @Test void approvalProducesVerifiableTenantBoundAuditRecord() {
        var result = service.prepare(pending(),
                new ApprovalWorkflow.Actor("tenant-a", "bob", true),
                ApprovalWorkflow.Action.APPROVE, 0, NOW.plusSeconds(1), List.of());
        assertEquals(ApprovalWorkflow.Status.APPROVED, result.updatedRequest().status());
        assertEquals(1, result.updatedRequest().version());
        assertEquals("ACCESS_REQUEST_APPROVE", result.auditEvent().action());
        assertEquals("bob", result.auditEvent().actorId());
        assertEquals("req-1", result.auditEvent().targetId());
        assertTrue(chain.verify("tenant-a", List.of(result.auditEvent())));
    }

    @Test void subsequentTransitionAppendsAfterExistingAuditHistory() {
        var first = chain.append("tenant-a", "system", "REQUEST_CREATED",
                "req-1", NOW, List.of());
        var result = service.prepare(pending(),
                new ApprovalWorkflow.Actor("tenant-a", "bob", true),
                ApprovalWorkflow.Action.REJECT, 0, NOW.plusSeconds(1), List.of(first));
        assertEquals(2, result.auditEvent().sequence());
        assertEquals(first.hash(), result.auditEvent().previousHash());
        assertTrue(chain.verify("tenant-a", List.of(first, result.auditEvent())));
    }

    @Test void crossTenantReviewerCannotProduceEvent() {
        assertThrows(SecurityException.class, () -> service.prepare(pending(),
                new ApprovalWorkflow.Actor("tenant-b", "bob", true),
                ApprovalWorkflow.Action.APPROVE, 0, NOW, List.of()));
    }

    @Test void selfApprovalCannotProduceEvent() {
        assertThrows(SecurityException.class, () -> service.prepare(pending(),
                new ApprovalWorkflow.Actor("tenant-a", "alice", true),
                ApprovalWorkflow.Action.APPROVE, 0, NOW, List.of()));
    }

    @Test void staleVersionCannotProduceEvent() {
        assertThrows(IllegalStateException.class, () -> service.prepare(pending(),
                new ApprovalWorkflow.Actor("tenant-a", "bob", true),
                ApprovalWorkflow.Action.APPROVE, 5, NOW, List.of()));
    }

    @Test void corruptedAuditHistoryIsRejected() {
        var foreign = chain.append("tenant-b", "system", "REQUEST_CREATED",
                "req-1", NOW, List.of());
        assertThrows(IllegalArgumentException.class, () -> service.prepare(pending(),
                new ApprovalWorkflow.Actor("tenant-a", "bob", true),
                ApprovalWorkflow.Action.APPROVE, 0, NOW, List.of(foreign)));
    }

    @Test void cancellationIsAttributedToRequester() {
        var result = service.prepare(pending(),
                new ApprovalWorkflow.Actor("tenant-a", "alice", false),
                ApprovalWorkflow.Action.CANCEL, 0, NOW, List.of());
        assertEquals(ApprovalWorkflow.Status.CANCELLED, result.updatedRequest().status());
        assertEquals("alice", result.auditEvent().actorId());
    }
}
