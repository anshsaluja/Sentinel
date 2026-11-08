package dev.sentinel.approval;

import java.time.Clock;
import java.util.List;
import java.util.Objects;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;

/**
 * Persists approval state transitions using Mongo @Version optimistic locking.
 *
 * This deliberately does NOT finalize an audited approval workflow: an
 * atomic audit write is still required before exposing this operation as an
 * authenticated API. Callers must not use this service as a security grant.
 */
@Service
public class ApprovalPersistenceService {
    private final ApprovalRepository repository;
    private final ApprovalWorkflow workflow = new ApprovalWorkflow();
    private final Clock clock;

    public ApprovalPersistenceService(ApprovalRepository repository) {
        this(repository, Clock.systemUTC());
    }

    ApprovalPersistenceService(ApprovalRepository repository, Clock clock) {
        this.repository = Objects.requireNonNull(repository);
        this.clock = Objects.requireNonNull(clock);
    }

    public ApprovalWorkflow.Request find(String tenantId, String requestId) {
        requireText(tenantId);
        requireText(requestId);
        ApprovalDocument document = repository.findByIdAndTenantId(requestId, tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Approval not found"));
        if (!tenantId.equals(document.tenantId))
            throw new SecurityException("Cross-tenant approval record");
        return document.toDomain();
    }

    public List<ApprovalWorkflow.Request> pending(String tenantId) {
        requireText(tenantId);
        return repository.findByTenantIdAndStatusOrderByUpdatedAtDesc(
                tenantId, ApprovalWorkflow.Status.PENDING).stream().map(doc -> {
            if (!tenantId.equals(doc.tenantId))
                throw new SecurityException("Cross-tenant approval record");
            return doc.toDomain();
        }).toList();
    }

    public ApprovalWorkflow.Request transition(String requestId, ApprovalWorkflow.Actor actor,
                                                ApprovalWorkflow.Action action, long expectedVersion) {
        Objects.requireNonNull(actor);
        ApprovalWorkflow.Request current = find(actor.tenantId(), requestId);
        ApprovalWorkflow.Request updated = workflow.apply(
                current, actor, action, expectedVersion, clock.instant()).request();
        // The version must be the version read from Mongo. Spring Data
        // increments it when saving; writing the incremented domain version
        // would otherwise cause a false optimistic-lock conflict.
        ApprovalDocument document = new ApprovalDocument(updated);
        document.version = current.version();
        try {
            ApprovalDocument saved = repository.save(document);
            if (!actor.tenantId().equals(saved.tenantId))
                throw new SecurityException("Cross-tenant approval save result");
            return saved.toDomain();
        } catch (OptimisticLockingFailureException conflict) {
            throw new IllegalStateException("Approval changed concurrently", conflict);
        }
    }

    private static void requireText(String value) {
        if (value == null || value.isBlank())
            throw new IllegalArgumentException("Required identifier missing");
    }
}
