package dev.sentinel.approval;

import dev.sentinel.audit.AuditDocument;
import dev.sentinel.audit.AuditHistoryService;
import dev.sentinel.audit.AuditRepository;
import java.time.Clock;
import java.util.Objects;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Commits an approval transition and its audit event in one MongoDB transaction.
 * Requires a MongoDB replica set and MongoTransactionManager; standalone MongoDB
 * is intentionally unsupported for this operation.
 *
 * Callers must derive Actor from a validated identity token, never from a
 * request body. No permission grant is provisioned by this service.
 */
@Service
public class TransactionalApprovalService {
    private final ApprovalRepository approvals;
    private final AuditRepository audits;
    private final AuditHistoryService history;
    private final ApprovalAuditService coordinator = new ApprovalAuditService();
    private final Clock clock;

    public TransactionalApprovalService(ApprovalRepository approvals, AuditRepository audits,
                                        AuditHistoryService history) {
        this(approvals, audits, history, Clock.systemUTC());
    }

    TransactionalApprovalService(ApprovalRepository approvals, AuditRepository audits,
                                 AuditHistoryService history, Clock clock) {
        this.approvals = Objects.requireNonNull(approvals);
        this.audits = Objects.requireNonNull(audits);
        this.history = Objects.requireNonNull(history);
        this.clock = Objects.requireNonNull(clock);
    }

    @Transactional
    public ApprovalWorkflow.Request transition(String requestId, ApprovalWorkflow.Actor actor,
                                                ApprovalWorkflow.Action action, long expectedVersion) {
        Objects.requireNonNull(actor, "actor");
        Objects.requireNonNull(action, "action");
        if (requestId == null || requestId.isBlank())
            throw new IllegalArgumentException("Request ID required");
        if (actor.tenantId() == null || actor.tenantId().isBlank())
            throw new IllegalArgumentException("Tenant ID required");

        ApprovalDocument current = approvals.findByIdAndTenantId(requestId, actor.tenantId())
                .orElseThrow(() -> new IllegalArgumentException("Approval not found"));
        if (!actor.tenantId().equals(current.tenantId))
            throw new SecurityException("Cross-tenant approval record");

        var prepared = coordinator.prepare(current.toDomain(), actor, action,
                expectedVersion, clock.instant(), history.verifiedHistory(actor.tenantId()));
        ApprovalDocument updated = new ApprovalDocument(prepared.updatedRequest());
        // Spring Data uses the version read from Mongo to enforce compare-and-swap.
        updated.version = current.version;
        try {
            ApprovalDocument saved = approvals.save(updated);
            if (!actor.tenantId().equals(saved.tenantId))
                throw new SecurityException("Cross-tenant approval save result");
            audits.save(new AuditDocument(prepared.auditEvent()));
            return saved.toDomain();
        } catch (OptimisticLockingFailureException conflict) {
            throw new IllegalStateException("Approval changed concurrently", conflict);
        }
        // Any audit insert failure must propagate, rolling back the approval
        // update. Never catch-and-ignore duplicate sequence conflicts.
    }
}
