package dev.sentinel.approval;

import org.junit.jupiter.api.Test;
import java.time.Instant;
import static org.junit.jupiter.api.Assertions.*;

class ApprovalWorkflowTest {
    private final ApprovalWorkflow workflow = new ApprovalWorkflow();
    private static final Instant NOW = Instant.parse("2026-11-08T00:00:00Z");

    private ApprovalWorkflow.Request pending() {
        return new ApprovalWorkflow.Request("request-1", "tenant-a", "alice", null,
                "ledger", "temporary read access", ApprovalWorkflow.Status.PENDING, 0, NOW);
    }
    private ApprovalWorkflow.Actor reviewer() {
        return new ApprovalWorkflow.Actor("tenant-a", "bob", true);
    }

    @Test void reviewerCanApproveAndIncrementVersion() {
        var transition = workflow.apply(pending(), reviewer(), ApprovalWorkflow.Action.APPROVE, 0, NOW);
        assertEquals(ApprovalWorkflow.Status.APPROVED, transition.request().status());
        assertEquals("bob", transition.request().approverId());
        assertEquals(1, transition.request().version());
    }
    @Test void reviewerCanReject() {
        assertEquals(ApprovalWorkflow.Status.REJECTED,
                workflow.apply(pending(), reviewer(), ApprovalWorkflow.Action.REJECT, 0, NOW).request().status());
    }
    @Test void requesterCanCancel() {
        assertEquals(ApprovalWorkflow.Status.CANCELLED,
                workflow.apply(pending(), new ApprovalWorkflow.Actor("tenant-a", "alice", false),
                        ApprovalWorkflow.Action.CANCEL, 0, NOW).request().status());
    }
    @Test void crossTenantReviewDenied() {
        assertThrows(SecurityException.class, () -> workflow.apply(pending(),
                new ApprovalWorkflow.Actor("tenant-b", "bob", true), ApprovalWorkflow.Action.APPROVE, 0, NOW));
    }
    @Test void selfApprovalDenied() {
        assertThrows(SecurityException.class, () -> workflow.apply(pending(),
                new ApprovalWorkflow.Actor("tenant-a", "alice", true), ApprovalWorkflow.Action.APPROVE, 0, NOW));
    }
    @Test void reviewerPermissionRequired() {
        assertThrows(SecurityException.class, () -> workflow.apply(pending(),
                new ApprovalWorkflow.Actor("tenant-a", "bob", false), ApprovalWorkflow.Action.REJECT, 0, NOW));
    }
    @Test void staleVersionDenied() {
        assertThrows(IllegalStateException.class,
                () -> workflow.apply(pending(), reviewer(), ApprovalWorkflow.Action.APPROVE, 1, NOW));
    }
    @Test void finalizedRequestCannotTransitionAgain() {
        var approved = workflow.apply(pending(), reviewer(), ApprovalWorkflow.Action.APPROVE, 0, NOW);
        assertThrows(IllegalStateException.class,
                () -> workflow.apply(approved.request(), reviewer(), ApprovalWorkflow.Action.REJECT, 1, NOW));
    }
    @Test void nonRequesterCannotCancel() {
        assertThrows(SecurityException.class,
                () -> workflow.apply(pending(), reviewer(), ApprovalWorkflow.Action.CANCEL, 0, NOW));
    }
    @Test void timestampCannotGoBackwards() {
        assertThrows(IllegalArgumentException.class,
                () -> workflow.apply(pending(), reviewer(), ApprovalWorkflow.Action.APPROVE, 0, NOW.minusSeconds(1)));
    }
}
