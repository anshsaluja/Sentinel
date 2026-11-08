package dev.sentinel.audit;

import java.util.List;
import java.util.Objects;
import org.springframework.stereotype.Service;

/**
 * Read-only verified audit history. No append operation is exposed until
 * the approval/audit transaction boundary and replica-set support exist.
 */
@Service
public class AuditHistoryService {
    private final AuditRepository repository;
    private final AuditChain chain = new AuditChain();

    public AuditHistoryService(AuditRepository repository) {
        this.repository = Objects.requireNonNull(repository);
    }

    public List<AuditChain.Event> verifiedHistory(String tenantId) {
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("Tenant is required");
        }
        List<AuditChain.Event> events = repository.findByTenantIdOrderBySequenceAsc(tenantId)
                .stream().map(document -> {
                    if (document == null || !tenantId.equals(document.tenantId)) {
                        throw new SecurityException("Cross-tenant audit record");
                    }
                    return document.toDomain();
                }).toList();
        if (!chain.verify(tenantId, events)) {
            throw new IllegalStateException("Audit history integrity check failed");
        }
        return events;
    }
}
