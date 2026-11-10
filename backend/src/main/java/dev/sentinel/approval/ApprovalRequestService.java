package dev.sentinel.approval;

import dev.sentinel.audit.AuditChain;
import dev.sentinel.audit.AuditDocument;
import dev.sentinel.audit.AuditHistoryService;
import dev.sentinel.audit.AuditRepository;
import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Creates a pending request and its audit event atomically. A request does not
 * provision permissions; it only starts a review. Requires a Mongo replica set.
 */
@Service
public class ApprovalRequestService {
    private final ApprovalRepository approvals;
    private final AuditRepository audits;
    private final AuditHistoryService history;
    private final Clock clock;
    private final AuditChain chain = new AuditChain();

    public ApprovalRequestService(ApprovalRepository approvals, AuditRepository audits,
                                  AuditHistoryService history) {
        this(approvals, audits, history, Clock.systemUTC());
    }

    ApprovalRequestService(ApprovalRepository approvals, AuditRepository audits,
                           AuditHistoryService history, Clock clock) {
        this.approvals = Objects.requireNonNull(approvals);
        this.audits = Objects.requireNonNull(audits);
        this.history = Objects.requireNonNull(history);
        this.clock = Objects.requireNonNull(clock);
    }

    @Transactional
    public ApprovalWorkflow.Request create(String tenantId, String requesterId,
                                            String resourceId, String justification) {
        require(tenantId, 120, "tenant");
        require(requesterId, 200, "requester");
        require(resourceId, 200, "resource");
        require(justification, 2000, "justification");
        var now = clock.instant().truncatedTo(ChronoUnit.MILLIS);
        var request = new ApprovalWorkflow.Request(UUID.randomUUID().toString(),
                tenantId, requesterId, null, resourceId, justification.trim(),
                ApprovalWorkflow.Status.PENDING, 0, now);
        var existing = history.verifiedHistory(tenantId);
        var event = chain.append(tenantId, requesterId, "REQUEST", request.id(), now, existing);
        // Mongo's unique (tenantId, sequence) index detects concurrent audit appends.
        // Any failure rolls back both writes; clients can retry with a new request.
        var saved = approvals.save(new ApprovalDocument(request));
        if (!tenantId.equals(saved.tenantId)) {
            throw new SecurityException("Cross-tenant approval save result");
        }
        audits.save(new AuditDocument(event));
        return saved.toDomain();
    }

    private static void require(String value, int max, String field) {
        if (value == null || value.isBlank() || value.length() > max) {
            throw new IllegalArgumentException("Invalid " + field);
        }
    }
}
