package dev.sentinel.approval;

import dev.sentinel.audit.AuditChain;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * Prepares an approval transition and its matching audit event without mutating state.
 * A persistence adapter MUST atomically commit both records (and use optimistic
 * version checks) before treating the approval as finalized.
 */
public final class ApprovalAuditService {
    private final ApprovalWorkflow workflow = new ApprovalWorkflow();
    private final AuditChain chain = new AuditChain();

    public record PreparedTransition(ApprovalWorkflow.Request updatedRequest,
                                     AuditChain.Event auditEvent) {
        public PreparedTransition {
            Objects.requireNonNull(updatedRequest);
            Objects.requireNonNull(auditEvent);
        }
    }

    public PreparedTransition prepare(ApprovalWorkflow.Request current,
                                      ApprovalWorkflow.Actor actor,
                                      ApprovalWorkflow.Action action,
                                      long expectedVersion,
                                      Instant occurredAt,
                                      List<AuditChain.Event> existingEvents) {
        Objects.requireNonNull(current, "current");
        Objects.requireNonNull(actor, "actor");
        Objects.requireNonNull(action, "action");
        Objects.requireNonNull(occurredAt, "occurredAt");
        Objects.requireNonNull(existingEvents, "existingEvents");

        // Validate audit history before producing any transition.
        if (!chain.verify(current.tenantId(), existingEvents)) {
            throw new IllegalArgumentException("Invalid audit history");
        }
        ApprovalWorkflow.Transition transition =
                workflow.apply(current, actor, action, expectedVersion, occurredAt);
        AuditChain.Event event = chain.append(
                current.tenantId(), actor.userId(), "ACCESS_REQUEST_" + action.name(),
                current.id(), occurredAt, existingEvents);
        return new PreparedTransition(transition.request(), event);
    }
}
