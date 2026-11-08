package dev.sentinel.approval;

import java.time.Instant;
import java.util.Objects;

/** Pure approval state machine. Persist transitions with optimistic locking in the application layer. */
public final class ApprovalWorkflow {
    public enum Status { PENDING, APPROVED, REJECTED, CANCELLED }
    public enum Action { APPROVE, REJECT, CANCEL }

    public record Request(String id, String tenantId, String requesterId, String approverId,
                          String resourceId, String justification, Status status,
                          long version, Instant updatedAt) {
        public Request {
            requireText(id, "id");
            requireText(tenantId, "tenantId");
            requireText(requesterId, "requesterId");
            requireText(resourceId, "resourceId");
            requireText(justification, "justification");
            Objects.requireNonNull(status, "status");
            Objects.requireNonNull(updatedAt, "updatedAt");
            if (version < 0) throw new IllegalArgumentException("version must be nonnegative");
            if (approverId != null && approverId.isBlank()) throw new IllegalArgumentException("blank approverId");
        }
    }

    public record Actor(String tenantId, String userId, boolean canReview) {
        public Actor {
            requireText(tenantId, "tenantId");
            requireText(userId, "userId");
        }
    }

    public record Transition(Request request, String actorId, Action action, Instant occurredAt) {}

    public Transition apply(Request current, Actor actor, Action action, long expectedVersion, Instant now) {
        Objects.requireNonNull(current, "current");
        Objects.requireNonNull(actor, "actor");
        Objects.requireNonNull(action, "action");
        Objects.requireNonNull(now, "now");
        if (!current.tenantId().equals(actor.tenantId())) throw new SecurityException("cross-tenant approval forbidden");
        if (expectedVersion != current.version()) throw new IllegalStateException("stale approval version");
        if (current.status() != Status.PENDING) throw new IllegalStateException("request already finalized");
        if (now.isBefore(current.updatedAt())) throw new IllegalArgumentException("timestamp precedes last update");
        final Status next;
        final String approver;
        switch (action) {
            case CANCEL -> {
                if (!current.requesterId().equals(actor.userId())) throw new SecurityException("only requester may cancel");
                next = Status.CANCELLED;
                approver = null;
            }
            case APPROVE, REJECT -> {
                if (!actor.canReview()) throw new SecurityException("review permission required");
                if (current.requesterId().equals(actor.userId())) throw new SecurityException("self-approval forbidden");
                next = action == Action.APPROVE ? Status.APPROVED : Status.REJECTED;
                approver = actor.userId();
            }
            default -> throw new IllegalStateException("unknown action");
        }
        Request updated = new Request(current.id(), current.tenantId(), current.requesterId(), approver,
                current.resourceId(), current.justification(), next, current.version() + 1, now);
        return new Transition(updated, actor.userId(), action, now);
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(field + " is required");
    }
}
